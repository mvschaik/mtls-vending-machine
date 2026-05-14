import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { Convert } from "pvtsutils";

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/**
 * Generates an ECDSA P-256 keypair using the Web Crypto API.
 */
export async function generateECDSAKeyPair(): Promise<KeyPair> {
  const algorithm: EcKeyGenParams = {
    name: "ECDSA",
    namedCurve: "P-256",
  };
  const keyPair = await globalThis.crypto.subtle.generateKey(
    algorithm,
    true,
    ["sign", "verify"]
  );
  return keyPair as KeyPair;
}

/**
 * Creates a CSR in PKCS#10 format using pkijs.
 */
export async function createCSR(keyPair: KeyPair, cn: string): Promise<string> {
  const pkcs10 = new pkijs.CertificationRequest();

  // Set the Subject
  pkcs10.subject.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({
      type: "2.5.4.3", // Common Name
      value: new asn1js.Utf8String({ value: cn }),
    })
  );

  // Import the public key
  await pkcs10.subjectPublicKeyInfo.importKey(keyPair.publicKey);

  // Explicitly initialize empty attributes to avoid ASN.1 parsing issues on some backends
  pkcs10.attributes = [];

  // Sign the CSR
  await pkcs10.sign(keyPair.privateKey, "SHA-256");

  // Export to PEM
  const csrBuffer = pkcs10.toSchema().toBER(false);
  const csrBase64 = Convert.ToBase64(csrBuffer);
  
  return `-----BEGIN CERTIFICATE REQUEST-----\n${formatBase64(csrBase64)}\n-----END CERTIFICATE REQUEST-----`;
}

function formatBase64(base64: string): string {
  const lines = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.substring(i, i + 64));
  }
  return lines.join("\n");
}

/**
 * Dummy CA function to return a hardcoded PEM ECDSA certificate for testing.
 */
export function dummyCASign(_csrPem: string): string {
  // A real self-signed ECDSA P-256 certificate for testing
  return `-----BEGIN CERTIFICATE-----
MIIBeDCCAR+gAwIBAgIUeu88i2zs214ND9+KZp5Jsbh+DIIwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHTW9jay1DQTAeFw0yNjA1MTIxOTEyNDhaFw0zNjA1MDkxOTEy
NDhaMBIxEDAOBgNVBAMMB01vY2stQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQUw56kq1jE4yGjMa4N08RsZiUuSs6U4q0rS7WoEjlHdP3S1INW3Vj7+uLx38um
BmDrB2+T1rXEc7lEDy29eqZMo1MwUTAdBgNVHQ4EFgQUmuEJIFMkhBfERJO89LLf
Jguh/OwwHwYDVR0jBBgwFoAUmuEJIFMkhBfERJO89LLfJguh/OwwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBtl6GLFf/ahQcWMCa9cw62cYqto/BZ
QE63a9LgjkVKtQIgXyXPDjTgbutg2m8Gukon1qYnHec5H95xmo/cEmTtrfo=
-----END CERTIFICATE-----`;
}

/**
 * Bundles the private key and the certificate chain into a password-protected .p12 file.
 */
export async function createP12Bundle(
  keyPair: KeyPair,
  certificateChainPems: string[],
  password: string
): Promise<ArrayBuffer> {
  const passwordBuffer = new TextEncoder().encode(password).buffer;

  // 1. Export the private key to PKCS#8
  const pkcs8Key = await globalThis.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const pkcs8 = new pkijs.PrivateKeyInfo({ schema: asn1js.fromBER(pkcs8Key).result });

  // 2. Create ShroudedKeyBag (Encrypted Private Key)
  const shroudedKeyBag = new pkijs.PKCS8ShroudedKeyBag({
    parsedValue: pkcs8
  });

  await shroudedKeyBag.makeInternalValues({
    password: passwordBuffer,
    iterationCount: 10000,
    hmacHashAlgorithm: "SHA-256",
    contentEncryptionAlgorithm: {
      name: "AES-CBC",
      length: 256
    } as any
  });

  const keySafeBag = new pkijs.SafeBag({
    bagId: "1.2.840.113549.1.12.10.1.2", // pkcs8ShroudedKeyBag
    bagValue: shroudedKeyBag
  });

  // 3. Create CertBags
  const certSafeBags: pkijs.SafeBag[] = [];
  for (const certPem of certificateChainPems) {
    const certBuffer = pemToArrayBuffer(certPem);
    const asn1 = asn1js.fromBER(certBuffer);
    if (asn1.offset === -1) {
      throw new Error("Error during parsing certificate ASN.1 data");
    }
    const cert = new pkijs.Certificate({ schema: asn1.result });
    
    const certBag = new pkijs.SafeBag({
      bagId: "1.2.840.113549.1.12.10.1.3", // certBag
      bagValue: new pkijs.CertBag({
        certValue: cert
      })
    });
    certSafeBags.push(certBag);
  }

  // 4. Construct AuthenticatedSafe
  // We put everything in SafeContents, wrap in OctetString, and put in ContentInfo (Data)
  const keySafeContents = new pkijs.SafeContents({
    safeBags: [keySafeBag]
  });

  const certSafeContents = new pkijs.SafeContents({
    safeBags: certSafeBags
  });

  const authSafe = new pkijs.AuthenticatedSafe({
    safeContents: [
      new pkijs.ContentInfo({
        contentType: "1.2.840.113549.1.7.1", // Data
        content: new asn1js.OctetString({ valueHex: keySafeContents.toSchema().toBER(false) })
      }),
      new pkijs.ContentInfo({
        contentType: "1.2.840.113549.1.7.1", // Data
        content: new asn1js.OctetString({ valueHex: certSafeContents.toSchema().toBER(false) })
      })
    ]
  });

  // 5. Create PFX and add MAC
  const pfx = new pkijs.PFX({
    parsedValue: {
      integrityMode: 0, // Password-based integrity
      authenticatedSafe: authSafe
    }
  });

  await pfx.makeInternalValues({
    password: passwordBuffer,
    iterations: 10000,
    pbkdf2HashAlgorithm: "SHA-256",
    hmacHashAlgorithm: "SHA-256"
  });

  return pfx.toSchema().toBER(false);
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s/g, "");
  return Convert.FromBase64(b64);
}

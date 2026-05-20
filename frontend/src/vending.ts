import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { Convert } from "pvtsutils";
import { OID } from "./oids";

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
      type: OID.commonName,
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
  password: string,
  friendlyName: string = "mTLS Certificate"
): Promise<ArrayBuffer> {
  const passwordBuffer = new TextEncoder().encode(password).buffer;

  // 1. Export the private key to PKCS#8
  const pkcs8Key = await globalThis.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const pkcs8 = new pkijs.PrivateKeyInfo({ schema: asn1js.fromBER(pkcs8Key).result });

  // 2. Generate attributes to link key and cert
  const localKeyId = globalThis.crypto.getRandomValues(new Uint8Array(20));
  const localKeyIdAttribute = new pkijs.Attribute({
    type: OID.localKeyId,
    values: [new asn1js.OctetString({ valueHex: localKeyId.buffer })]
  });

  const friendlyNameAttribute = new pkijs.Attribute({
    type: OID.friendlyName,
    values: [new asn1js.BmpString({ value: friendlyName })]
  });

  // 3. Create Private Key Bag (Unencrypted for now, will be encrypted in AuthenticatedSafe)
  const keySafeBag = new pkijs.SafeBag({
    bagId: OID.keyBag,
    bagValue: pkcs8,
    bagAttributes: [localKeyIdAttribute, friendlyNameAttribute]
  });

  // 4. Create CertBags
  const certSafeBags: pkijs.SafeBag[] = [];
  for (let i = 0; i < certificateChainPems.length; i++) {
    const certPem = certificateChainPems[i];
    const certBuffer = pemToArrayBuffer(certPem);
    const asn1 = asn1js.fromBER(certBuffer);
    if (asn1.offset === -1) {
      throw new Error("Error during parsing certificate ASN.1 data");
    }
    const cert = new pkijs.Certificate({ schema: asn1.result });
    
    const certBag = new pkijs.CertBag({
      certId: OID.x509Certificate,
      certValue: new asn1js.OctetString({ valueHex: cert.toSchema().toBER(false) })
    });

    const bagAttributes = [];
    if (i === 0) {
      bagAttributes.push(localKeyIdAttribute);
      bagAttributes.push(friendlyNameAttribute);
    }

    const certSafeBag = new pkijs.SafeBag({
      bagId: OID.certBag,
      bagValue: certBag,
      bagAttributes: bagAttributes
    });
    certSafeBags.push(certSafeBag);
  }

  // 5. Construct AuthenticatedSafe using parsedValue pattern
  const authSafe = new pkijs.AuthenticatedSafe({
    parsedValue: {
      safeContents: [
        {
          privacyMode: 1, // EncryptedData
          value: new pkijs.SafeContents({ safeBags: [keySafeBag] })
        },
        {
          privacyMode: 1, // EncryptedData
          value: new pkijs.SafeContents({ safeBags: certSafeBags })
        }
      ]
    }
  });

  // macOS and OpenSSL compatibility encryption settings
  const encryptionParams = {
    password: passwordBuffer,
    iterationCount: 10000,
    hmacHashAlgorithm: "SHA-256",
    contentEncryptionAlgorithm: {
      name: "AES-CBC",
      length: 256
    }
  };

  await authSafe.makeInternalValues({
    safeContents: [encryptionParams, encryptionParams]
  });

  // 6. Create PFX and add MAC
  const pfx = new pkijs.PFX({
    parsedValue: {
      integrityMode: 0, // Password-based HMAC
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

import forge from 'node-forge';

export interface KeyPair {
  publicKey: forge.pki.rsa.PublicKey;
  privateKey: forge.pki.rsa.PrivateKey;
}

export async function generateRSAKeyPair(bits: number = 2048): Promise<KeyPair> {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits, workers: -1 }, (err, keypair) => {
      if (err) reject(err);
      else resolve(keypair);
    });
  });
}

export function createCSR(keypair: KeyPair, cn: string): string {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keypair.publicKey;
  csr.setSubject([{
    name: 'commonName',
    value: cn
  }]);
  csr.sign(keypair.privateKey);
  return forge.pki.certificationRequestToPem(csr);
}

export function stripCertParameters(cert: forge.pki.Certificate): void {
  // 1. Clears the 'inner' signature parameters (inside TBSCertificate)
  (cert as any).signatureParameters = undefined;

  // 2. Clears the 'outer' signature parameters (the wrapper)
  if ((cert as any).sigAlg) {
    (cert as any).sigAlg.parameters = undefined;
  }

  // 3. Some versions of Forge use 'md' for the digest algorithm block
  if ((cert as any).md && (cert as any).md.parameters) {
    (cert as any).md.parameters = undefined;
  }
}

export function createP12Bundle(
  keypair: KeyPair,
  signedCertPem: string,
  rootCaPem: string | null,
  password: string
): string {
  const certs: forge.pki.Certificate[] = [];
  
  const cert = forge.pki.certificateFromPem(signedCertPem);
  // Explicitly link the local public key to ensure Forge is happy
  cert.publicKey = keypair.publicKey;
  certs.push(cert);

  if (rootCaPem) {
    try {
      const rootCert = forge.pki.certificateFromPem(rootCaPem);
      certs.push(rootCert);
    } catch (e) {
      console.warn("Notice: Could not include Root CA in the .p12 bundle because its format (likely ECDSA) is not supported by the local bundler. The bundle will still contain your client identity.", e);
    }
  }

  certs.forEach(stripCertParameters);

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    keypair.privateKey,
    certs,
    password,
    {
      algorithm: 'aes256',
      generateLocalKeyId: true
    }
  );

  return forge.asn1.toDer(p12Asn1).getBytes();
}

import { describe, it, expect } from 'vitest';
import { generateECDSAKeyPair, createCSR, createP12Bundle } from './vending';
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { Convert } from "pvtsutils";

describe('vending logic (pkijs/WebCrypto)', () => {
  it('should generate a valid ECDSA P-256 keypair', async () => {
    const keypair = await generateECDSAKeyPair();
    expect(keypair.publicKey).toBeDefined();
    expect(keypair.privateKey).toBeDefined();
    expect(keypair.publicKey.algorithm.name).toBe('ECDSA');
    // @ts-ignore
    expect(keypair.publicKey.algorithm.namedCurve).toBe('P-256');
  });

  it('should create a valid CSR', async () => {
    const keypair = await generateECDSAKeyPair();
    const pem = await createCSR(keypair, 'test-user');
    expect(pem).toContain('-----BEGIN CERTIFICATE REQUEST-----');
    
    // Verify CSR with pkijs
    const b64 = pem.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s/g, "");
    const der = Convert.FromBase64(b64);
    const asn1 = asn1js.fromBER(der);
    const csr = new pkijs.CertificationRequest({ schema: asn1.result });
    
    const cnField = csr.subject.typesAndValues.find(tv => tv.type === "2.5.4.3");
    expect(cnField).toBeDefined();
    expect(cnField?.value.valueBlock.value).toBe('test-user');
    
    const verified = await csr.verify();
    expect(verified).toBe(true);
  });

  it('should create a valid P12 bundle with full chain and 3DES', async () => {
    const keypair = await generateECDSAKeyPair();
    
    // Create a self-signed cert for testing using pkijs
    const cert = new pkijs.Certificate();
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: 1 });
    cert.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
      type: "2.5.4.3",
      value: new asn1js.Utf8String({ value: "test-user" })
    }));
    cert.issuer.typesAndValues.push(new pkijs.AttributeTypeAndValue({
      type: "2.5.4.3",
      value: new asn1js.Utf8String({ value: "test-user" })
    }));
    cert.notBefore.value = new Date();
    cert.notAfter.value = new Date();
    cert.notAfter.value.setFullYear(cert.notBefore.value.getFullYear() + 1);
    
    await cert.subjectPublicKeyInfo.importKey(keypair.publicKey);
    await cert.sign(keypair.privateKey, "SHA-256");
    
    const certBuffer = cert.toSchema().toBER(false);
    const certPem = `-----BEGIN CERTIFICATE-----\n${Convert.ToBase64(certBuffer)}\n-----END CERTIFICATE-----`;

    // Create a mock root CA
    const rootCert = new pkijs.Certificate();
    rootCert.version = 2;
    rootCert.serialNumber = new asn1js.Integer({ value: 2 });
    rootCert.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
      type: "2.5.4.3",
      value: new asn1js.Utf8String({ value: "Mock-Root-CA" })
    }));
    rootCert.issuer.typesAndValues.push(new pkijs.AttributeTypeAndValue({
      type: "2.5.4.3",
      value: new asn1js.Utf8String({ value: "Mock-Root-CA" })
    }));
    rootCert.notBefore.value = new Date();
    rootCert.notAfter.value = new Date();
    rootCert.notAfter.value.setFullYear(rootCert.notBefore.value.getFullYear() + 10);
    
    const rootKeypair = await generateECDSAKeyPair();
    await rootCert.subjectPublicKeyInfo.importKey(rootKeypair.publicKey);
    await rootCert.sign(rootKeypair.privateKey, "SHA-256");
    const rootCertPem = `-----BEGIN CERTIFICATE-----\n${Convert.ToBase64(rootCert.toSchema().toBER(false))}\n-----END CERTIFICATE-----`;

    const p12Buffer = await createP12Bundle(keypair, [certPem, rootCertPem], 'password');
    
    expect(p12Buffer).toBeDefined();
    expect(p12Buffer.byteLength).toBeGreaterThan(0);
    
    // PKCS#12 is ASN.1 DER, should start with 0x30 (SEQUENCE)
    const view = new Uint8Array(p12Buffer);
    expect(view[0]).toBe(0x30);

    // Verify P12 structure with pkijs
    const p12Asn1 = asn1js.fromBER(p12Buffer);
    const pfx = new pkijs.PFX({ schema: p12Asn1.result });
    expect(pfx).toBeDefined();
    expect(pfx.version).toBe(3);
    expect(pfx.authSafe).toBeDefined();
    expect(pfx.macData).toBeDefined();
  });
});

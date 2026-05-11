import { describe, it, expect } from 'vitest';
import { generateRSAKeyPair, createCSR } from './vending';
import forge from 'node-forge';

describe('vending logic', () => {
  it('should generate a valid RSA keypair', async () => {
    const keypair = await generateRSAKeyPair(1024); // smaller for faster tests
    expect(keypair.publicKey).toBeDefined();
    expect(keypair.privateKey).toBeDefined();
  });

  it('should create a valid CSR', async () => {
    const keypair = await generateRSAKeyPair(1024);
    const pem = createCSR(keypair, 'test-user');
    expect(pem).toContain('-----BEGIN CERTIFICATE REQUEST-----');
    
    const csr = forge.pki.certificationRequestFromPem(pem);
    expect(csr.subject.getField('CN').value).toBe('test-user');
    expect(csr.verify()).toBe(true);
  });

  it('should create a valid P12 bundle', async () => {
    const keypair = await generateRSAKeyPair(1024);
    
    // Create a self-signed cert for testing
    const cert = forge.pki.createCertificate();
    cert.publicKey = keypair.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    cert.setSubject([{ name: 'commonName', value: 'test-user' }]);
    cert.setIssuer([{ name: 'commonName', value: 'test-user' }]);
    cert.sign(keypair.privateKey);
    const certPem = forge.pki.certificateToPem(cert);

    const { createP12Bundle } = await import('./vending');
    const p12Der = createP12Bundle(keypair, certPem, null, 'password');
    
    expect(p12Der).toBeDefined();
    expect(p12Der.length).toBeGreaterThan(0);
    
    // PKCS#12 is ASN.1 DER, should start with 0x30 (SEQUENCE)
    expect(p12Der.charCodeAt(0)).toBe(0x30);
  });
});

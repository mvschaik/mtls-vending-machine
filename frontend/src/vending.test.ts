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
});

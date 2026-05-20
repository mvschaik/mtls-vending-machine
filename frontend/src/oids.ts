/**
 * Object Identifiers (OIDs) used in the mTLS Vending Machine.
 */
export const OID = {
  /** Common Name */
  commonName: "2.5.4.3",

  /** PKCS#9 localKeyId */
  localKeyId: "1.2.840.113549.1.9.21",

  /** PKCS#9 friendlyName */
  friendlyName: "1.2.840.113549.1.9.20",

  /** PKCS#12 keyBag */
  keyBag: "1.2.840.113549.1.12.10.1.1",

  /** PKCS#9 x509Certificate */
  x509Certificate: "1.2.840.113549.1.9.22.1",

  /** PKCS#12 certBag */
  certBag: "1.2.840.113549.1.12.10.1.3",
} as const;

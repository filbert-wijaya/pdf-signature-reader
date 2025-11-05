const tls = require('tls');
const forge = require('node-forge');
const rootCAs = require('./rootCAs');

const getRootCAs = (customCAs = []) => {
  const defaultCAs = tls.rootCertificates || rootCAs;
  return [...defaultCAs, ...customCAs];
};

const verifyRootCert = (chainRootInForgeFormat, customCAs = []) => !!getRootCAs(customCAs)
  .find((rootCAInPem) => {
    try {
      const rootCAInForgeCert = forge.pki.certificateFromPem(rootCAInPem);
      return forge.pki.certificateToPem(chainRootInForgeFormat) === rootCAInPem
      || rootCAInForgeCert.issued(chainRootInForgeFormat);
    } catch (e) {
      return false;
    }
  });

const verifyCaBundle = (certs) => !!certs
  .find((cert, i) => certs[i + 1] && certs[i + 1].issued(cert));

const isCertsExpired = (certs) => !!certs
  .find(({ validity: { notAfter, notBefore } }) => notAfter.getTime() < Date.now()
  || notBefore.getTime() > Date.now());

const authenticateSignature = (certs, customCAs = []) => {
  // Handle self-signed leaf
  if (certs.length === 1) {
    const leafPem = forge.pki.certificateToPem(certs[0]);
    if (customCAs.includes(leafPem)) return true;
  }
  verifyCaBundle(certs) && verifyRootCert(certs[certs.length - 1], customCAs)
};

module.exports = {
  authenticateSignature,
  verifyCaBundle,
  verifyRootCert,
  isCertsExpired,
};
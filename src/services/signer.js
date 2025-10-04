import fs from "fs";
import forge from "node-forge";

export function simulateSignature() {
  if (!process.env.CERT_PATH || !process.env.CERT_PASS) {
    throw new Error("Certificate path or password not configured");
  }

  const p12Buffer = fs.readFileSync(process.env.CERT_PATH);
  const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString("binary"));
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, process.env.CERT_PASS);

  const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]?.[0];
  if (!certBag?.cert) {
    throw new Error("Certificate not found inside the provided P12 file");
  }

  const cert = forge.pki.certificateToPem(certBag.cert);

  return `SimulatedSignature:${Buffer.from(cert).toString("base64").slice(0, 64)}...`;
}

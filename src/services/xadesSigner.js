// Firma XMLDSig (RSA-SHA256) del nodo <sum1:RegistroAlta> (firma "enveloped")
// Requisitos: xml-crypto ^6, @xmldom/xmldom, node-forge, xpath
// Usa CERT_PATH y CERT_PASS del .env

import fs from "fs";
import path from "path";
import forge from "node-forge";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import xpath from "xpath";
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { SignedXml } = require("xml-crypto");

const C14N_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const TR_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

function loadPkcs12(p12Path, passphrase = "") {
  const absPath = path.isAbsolute(p12Path) ? p12Path : path.join(process.cwd(), p12Path);
  const p12Bytes = fs.readFileSync(absPath);
  const p12Der = forge.util.createBuffer(p12Bytes.toString("binary"));
  const asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, passphrase);

  let privateKeyPem = null;
  let certificatePem = null;

  for (const sc of p12.safeContents) {
    for (const sb of sc.safeBags) {
      if (sb.type === forge.pki.oids.pkcs8ShroudedKeyBag || sb.type === forge.pki.oids.keyBag) {
        privateKeyPem = forge.pki.privateKeyToPem(sb.key);
      }
      if (sb.type === forge.pki.oids.certBag) {
        certificatePem = forge.pki.certificateToPem(sb.cert);
      }
    }
  }
  if (!privateKeyPem || !certificatePem) throw new Error("No se pudo extraer clave/cert del .p12");

  const certB64 = certificatePem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\r?\n|\r/g, "");

  return { privateKeyPem, certificatePem, certB64 };
}

function stripSimulatedSignature(xml) {
  return xml.replace(/<\s*sum1:SimulatedSignature[^>]*>[\s\S]*?<\s*\/\s*sum1:SimulatedSignature\s*>/gi, "");
}

function ensureRegistroAltaHasId(doc) {
  const regAlta = xpath.select("//*[local-name()='RegistroAlta']", doc)[0];
  if (!regAlta) throw new Error("No se encontró <sum1:RegistroAlta> en el XML");
  if (!regAlta.getAttribute("Id") && !regAlta.getAttribute("ID") && !regAlta.getAttribute("id")) {
    regAlta.setAttribute("Id", "RegistroAlta-1");
  }
  return regAlta;
}

function buildKeyInfo(certB64) {
  // <ds:KeyInfo> mínimo con el X509
  return `<X509Data><X509Certificate>${certB64}</X509Certificate></X509Data>`;
}

export function signXmlWithXades(xmlUnsigned) {
  const p12Path = process.env.CERT_PATH;
  const p12Pass = process.env.CERT_PASS || "";
  if (!p12Path) throw new Error("CERT_PATH no definido");

  const { privateKeyPem, certificatePem, certB64 } = loadPkcs12(p12Path, p12Pass);

  // 1) Quitar placeholder si existe
  const xmlClean = stripSimulatedSignature(xmlUnsigned);

  // 2) Asegurar Id en RegistroAlta
  const doc = new DOMParser().parseFromString(xmlClean, "text/xml");
  ensureRegistroAltaHasId(doc);
  const xmlPrepared = new XMLSerializer().serializeToString(doc);

  // 3) Configurar firma XMLDSig (enveloped sobre RegistroAlta)
  const sig = new SignedXml({
    privateKey: Buffer.from(privateKeyPem),
    publicCert: Buffer.from(certificatePem),
    signatureAlgorithm: SIG_RSA_SHA256,
    canonicalizationAlgorithm: C14N_EXC,
  });

  // KeyInfo con el certificado
  sig.getKeyInfoContent = () => buildKeyInfo(certB64);

  // Referencia: TODO el contenido de RegistroAlta (enveloped + c14n-excl), digest SHA-256
  sig.addReference({
    xpath: "//*[local-name(.)='RegistroAlta']",
    transforms: [TR_ENVELOPED, C14N_EXC],
    digestAlgorithm: DIGEST_SHA256,
  });

  // 4) Calcular e insertar <ds:Signature> dentro de RegistroAlta
  sig.computeSignature(xmlPrepared, {
    prefix: "ds",
    location: { reference: "//*[local-name(.)='RegistroAlta']", action: "append" },
  });

  return sig.getSignedXml();
}

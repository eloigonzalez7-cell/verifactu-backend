// Firma XMLDSig (RSA-SHA256) del nodo <sum1:RegistroAlta> (firma "enveloped")
// Requisitos: xml-crypto@1.5.3, @xmldom/xmldom, node-forge, xpath
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
      if ((sb.type === forge.pki.oids.pkcs8ShroudedKeyBag || sb.type === forge.pki.oids.keyBag) && sb.key) {
        privateKeyPem = forge.pki.privateKeyToPem(sb.key);
      }
      if (sb.type === forge.pki.oids.certBag && sb.cert) {
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
  // Elimina el placeholder (si existe)
  return xml.replace(/<\s*sum1:SimulatedSignature[^>]*>[\s\S]*?<\s*\/\s*sum1:SimulatedSignature\s*>/gi, "");
}

function ensureRegistroAltaHasId(doc) {
  // Asegura atributo Id en <sum1:RegistroAlta>
  const regAlta = xpath.select("//*[local-name()='RegistroAlta']", doc)[0];
  if (!regAlta) throw new Error("No se encontró <sum1:RegistroAlta> en el XML");
  if (!regAlta.getAttribute("Id") && !regAlta.getAttribute("ID") && !regAlta.getAttribute("id")) {
    regAlta.setAttribute("Id", "RegistroAlta-1");
  }
  return regAlta.getAttribute("Id") || regAlta.getAttribute("ID") || regAlta.getAttribute("id");
}

function keyInfoWithCert(certB64) {
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
  const regId = ensureRegistroAltaHasId(doc);
  const xmlPrepared = new XMLSerializer().serializeToString(doc);

  // 3) Configurar firma XMLDSig (enveloped sobre RegistroAlta)
  const sig = new SignedXml({
    privateKey: Buffer.from(privateKeyPem),
    publicCert: Buffer.from(certificatePem),
    signatureAlgorithm: SIG_RSA_SHA256,
    canonicalizationAlgorithm: C14N_EXC,
  });

  // KeyInfo con el certificado
  sig.getKeyInfoContent = () => keyInfoWithCert(certB64);

  // 4) Referencia: TODO el contenido de RegistroAlta (enveloped + c14n-excl), digest SHA-256
  //    ✅ Usamos la API clásica de xml-crypto 1.5.3 (primer parámetro = XPath STRING)
  sig.addReference(
    "//*[local-name()='RegistroAlta']",
    [TR_ENVELOPED, C14N_EXC],
    DIGEST_SHA256,
    `#${regId}`,            // uri (coincide con el Id que acabamos de asegurar)
    "ref-obj-registro"     // id de la referencia
  );

  // 5) Calcular e insertar <ds:Signature> dentro de RegistroAlta
  sig.computeSignature(xmlPrepared, {
    prefix: "ds",
    // ✅ XPath con local-name() SIN punto (evita el parse error)
    location: { reference: "//*[local-name()='RegistroAlta']", action: "append" },
  });

  return sig.getSignedXml();
}

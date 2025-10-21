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
  const raw = fs.readFileSync(absPath);

  // DER -> ASN.1 -> PKCS#12
  const p12Der = forge.util.createBuffer(raw.toString("binary"));
  const asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, passphrase);

  const keys = [];
  const certs = [];

  for (const sc of p12.safeContents) {
    for (const sb of sc.safeBags) {
      if ((sb.type === forge.pki.oids.pkcs8ShroudedKeyBag || sb.type === forge.pki.oids.keyBag) && sb.key) {
        keys.push(forge.pki.privateKeyToPem(sb.key));
      }
      if (sb.type === forge.pki.oids.certBag && sb.cert) {
        certs.push(forge.pki.certificateToPem(sb.cert));
      }
    }
  }

  if (keys.length === 0) {
    throw new Error(`No se encontró clave privada en ${absPath}. ¿Contraseña correcta?`);
  }
  if (certs.length === 0) {
    throw new Error(`No se encontró certificado en ${absPath}.`);
  }

  const privateKeyPem = keys[0];       // usamos la primera
  const certificatePem = certs[0];     // certificado hoja

  // A partir de aquí SÍ podemos llamar a replace con seguridad
  const certB64 = certificatePem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\r?\n|\r/g, "");

  return { privateKeyPem, certB64 };
}

// Limpieza: sin placeholders ni comentarios antiguos
function stripPlaceholders(xml) {
  let out = xml.replace(
    /<\s*sum1:SimulatedSignature[^>]*>[\s\S]*?<\s*\/\s*sum1:SimulatedSignature\s*>/gi,
    ""
  );
  out = out.replace(
    /<!--\s*Marcador\s+que\s+será\s+reemplazado\s+por\s+<ds:Signature>\s*-->/gi,
    ""
  );
  return out.replace(/\n[ \t]*\n+/g, "\n");
}

function ensureRegistroAltaHasId(doc) {
  const regAlta = xpath.select("//*[local-name()='RegistroAlta']", doc)[0];
  if (!regAlta) throw new Error("No se encontró <sum1:RegistroAlta> en el XML");
  if (!regAlta.getAttribute("Id") && !regAlta.getAttribute("ID") && !regAlta.getAttribute("id")) {
    regAlta.setAttribute("Id", "RegistroAlta-1");
  }
  return regAlta.getAttribute("Id") || regAlta.getAttribute("ID") || regAlta.getAttribute("id");
}

function keyInfoWithCert(certB64) {
  // xml-crypto 1.5.3 envolverá esto dentro de <ds:KeyInfo>
  return `<X509Data><X509Certificate>${certB64}</X509Certificate></X509Data>`;
}

export function signXmlWithXades(xmlUnsigned) {
  const p12Path = process.env.CERT_PATH;
  const p12Pass = process.env.CERT_PASS || "";
  if (!p12Path) throw new Error("CERT_PATH no definido");

  // 1) Carga clave y certificado del .p12 (con errores claros si faltan)
  const { privateKeyPem, certB64 } = loadPkcs12(p12Path, p12Pass);

  // 2) Limpia placeholders
  const xmlClean = stripPlaceholders(xmlUnsigned);

  // 3) Asegura Id en <sum1:RegistroAlta>
  const doc = new DOMParser().parseFromString(xmlClean, "text/xml");
  const regId = ensureRegistroAltaHasId(doc);
  const xmlPrepared = new XMLSerializer().serializeToString(doc);

  // 4) Configurar xml-crypto (en 1.5.3 se setea en la instancia)
  const sig = new SignedXml();
  sig.signingKey = privateKeyPem;           // clave privada
  sig.signatureAlgorithm = SIG_RSA_SHA256;  // forzar RSA-SHA256
  sig.canonicalizationAlgorithm = C14N_EXC; // C14N exclusiva

  sig.keyInfoProvider = {
    getKeyInfo: () => keyInfoWithCert(certB64),
    getKey: () => null,
  };

  // 5) Referencia al nodo RegistroAlta (enveloped + c14n-excl), digest SHA-256
  sig.addReference(
    "//*[local-name()='RegistroAlta']",
    [TR_ENVELOPED, C14N_EXC],
    DIGEST_SHA256,
    `#${regId}`,
    "ref-obj-registro"
  );

  // 6) Firmar e insertar <ds:Signature> dentro de RegistroAlta
  sig.computeSignature(xmlPrepared, {
    prefix: "ds",
    location: { reference: "//*[local-name()='RegistroAlta']", action: "append" },
  });

  return sig.getSignedXml();
}

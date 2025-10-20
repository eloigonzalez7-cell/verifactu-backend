// Firma XML (XMLDSig enveloped) del nodo <sum1:RegistroAlta>
// Requisitos: xml-crypto ^6, @xmldom/xmldom, node-forge, xpath
// Usa el .p12 de pruebas indicado en .env (CERT_PATH y CERT_PASS)

const fs = require("fs");
const path = require("path");
const forge = require("node-forge");
const { SignedXml } = require("xml-crypto");
const { DOMParser, XMLSerializer } = require("@xmldom/xmldom");
const xpath = require("xpath");

const C14N_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const TR_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

function loadPkcs12(p12Path, passphrase) {
  const absPath = path.isAbsolute(p12Path) ? p12Path : path.join(process.cwd(), p12Path);
  const p12Bytes = fs.readFileSync(absPath);
  const p12Der = forge.util.createBuffer(p12Bytes.toString("binary"));
  const asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, passphrase || "");

  let privateKeyPem = null;
  let certificatePem = null;

  for (const safeContent of p12.safeContents) {
    for (const safeBag of safeContent.safeBags) {
      if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag || safeBag.type === forge.pki.oids.keyBag) {
        const pk = safeBag.key;
        privateKeyPem = forge.pki.privateKeyToPem(pk);
      }
      if (safeBag.type === forge.pki.oids.certBag) {
        const cert = safeBag.cert;
        certificatePem = forge.pki.certificateToPem(cert);
      }
    }
  }

  if (!privateKeyPem || !certificatePem) {
    throw new Error("No se pudo extraer clave privada y certificado del .p12");
  }

  const certB64 = certificatePem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\r?\n|\r/g, "");

  return { privateKeyPem, certificatePem, certB64 };
}

function stripSimulatedSignature(xml) {
  // Elimina el placeholder <sum1:SimulatedSignature>...</sum1:SimulatedSignature>
  return xml.replace(/<\s*sum1:SimulatedSignature[^>]*>[\s\S]*?<\s*\/\s*sum1:SimulatedSignature\s*>/gi, "");
}

function ensureRegistroAltaHasId(xmlDoc) {
  // Añadimos un Id estable al nodo <sum1:RegistroAlta> para evitar IDs auto (_0)
  const nsResolver = {
    sum1: "https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/SuministroInformacion.xsd",
  };
  const select = xpath.useNamespaces(nsResolver);
  const regAlta = select("//*[local-name()='RegistroAlta']", xmlDoc)[0];
  if (!regAlta) {
    throw new Error("No se encontró el nodo <sum1:RegistroAlta> en el XML a firmar");
  }
  // Si ya tiene Id/ID/id, lo respetamos
  if (!regAlta.getAttribute("Id") && !regAlta.getAttribute("ID") && !regAlta.getAttribute("id")) {
    regAlta.setAttribute("Id", "RegistroAlta-1");
  }
  return regAlta;
}

function buildKeyInfo(certB64) {
  // Incluimos el certificado en <ds:KeyInfo> -> <ds:X509Data>
  return `<X509Data><X509Certificate>${certB64}</X509Certificate></X509Data>`;
}

function signRegistroAlta(xmlString, p12Path, p12Pass) {
  const { privateKeyPem, certificatePem, certB64 } = loadPkcs12(p12Path, p12Pass);

  // 1) eliminar marcador SimulatedSignature si existe
  const xmlClean = stripSimulatedSignature(xmlString);

  // 2) parsear y asegurar Id en RegistroAlta
  const doc = new DOMParser().parseFromString(xmlClean, "text/xml");
  ensureRegistroAltaHasId(doc);
  const xmlPrepared = new XMLSerializer().serializeToString(doc);

  // 3) configurar firma
  const sig = new SignedXml({
    privateKey: Buffer.from(privateKeyPem),
    publicCert: Buffer.from(certificatePem),
    signatureAlgorithm: SIG_RSA_SHA256,
    canonicalizationAlgorithm: C14N_EXC,
  });

  // KeyInfo con X509Certificate en base64
  sig.getKeyInfoContent = () => buildKeyInfo(certB64);

  // Referencia al nodo RegistroAlta (enveloped + c14n exc)
  sig.addReference({
    xpath: "//*[local-name(.)='RegistroAlta']",
    transforms: [TR_ENVELOPED, C14N_EXC],
    digestAlgorithm: DIGEST_SHA256,
  });

  // 4) calcular firma, insertando <ds:Signature> dentro de RegistroAlta
  sig.computeSignature(xmlPrepared, {
    prefix: "ds",
    location: {
      reference: "//*[local-name(.)='RegistroAlta']",
      action: "append",
    },
  });

  return sig.getSignedXml();
}

module.exports = {
  /**
   * Firma el XML SOAP completo sobre el nodo sum1:RegistroAlta.
   * Lee CERT_PATH y CERT_PASS del entorno.
   */
  signEnvelopeXML: (xmlString) => {
    const p12Path = process.env.CERT_PATH;
    const p12Pass = process.env.CERT_PASS || "";
    if (!p12Path) throw new Error("CERT_PATH no definido en .env");
    return signRegistroAlta(xmlString, p12Path, p12Pass);
  },
};

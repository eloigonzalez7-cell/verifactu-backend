// Firma XAdES-EPES (RSA-SHA256) sobre <sum1:RegistroAlta> (firma enveloped)
// Requisitos: xml-crypto@1.5.3, node-forge, @xmldom/xmldom, xpath
// Lee CERT_PATH y CERT_PASS del entorno (.env)

import fs from "fs";
import path from "path";
import forge from "node-forge";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import xpath from "xpath";
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { SignedXml } = require("xml-crypto");

// Algoritmos
const C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const TR_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

// Política AGE (EPES)
const POLICY_OID = "urn:oid:2.16.724.1.3.1.1.2.1.9";
const POLICY_URL = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf";
const POLICY_HASH_ALG = "http://www.w3.org/2000/09/xmldsig#sha1";        // digest de la política
const POLICY_HASH_B64 = "G7roucf600+f03r/o0bAOQ6WAs0=";                    // SHA-1 del PDF de política

// Utils
function hexToDecString(hex) { return BigInt("0x" + hex.replace(/^0x/i, "")).toString(10); }
function b64Digest(buf, alg) { return forge.md[alg] ? null : null; } // (no usada aquí)
function sha1B64(buffer) {
  const md = forge.md.sha1.create();
  md.update(buffer.toString("binary"));
  return forge.util.encode64(md.digest().getBytes());
}

function loadPkcs12(p12Path, passphrase = "") {
  const absPath = path.isAbsolute(p12Path) ? p12Path : path.join(process.cwd(), p12Path);
  const raw = fs.readFileSync(absPath);
  const p12Der = forge.util.createBuffer(raw.toString("binary"));
  const asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, passphrase);

  let privateKeyPem = null;
  let certificatePem = null;
  let cert; // forge cert para DER y meta

  for (const sc of p12.safeContents) {
    for (const sb of sc.safeBags) {
      if ((sb.type === forge.pki.oids.pkcs8ShroudedKeyBag || sb.type === forge.pki.oids.keyBag) && sb.key) {
        privateKeyPem = forge.pki.privateKeyToPem(sb.key);
      }
      if (sb.type === forge.pki.oids.certBag && sb.cert) {
        cert = sb.cert;
        certificatePem = forge.pki.certificateToPem(sb.cert);
      }
    }
  }
  if (!privateKeyPem || !certificatePem || !cert) throw new Error("No se pudo extraer clave/cert del .p12");

  const certDerBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const certDerBuffer = Buffer.from(certDerBytes, "binary");
  const certB64 = certDerBuffer.toString("base64");

  const issuerName = cert.issuer.attributes.map(a => `${a.shortName || a.name}=${a.value}`).join(", ");
  const serialDec = hexToDecString(cert.serialNumber);

  return { privateKeyPem, certificatePem, certDerBuffer, certB64, issuerName, serialDec };
}

function stripSimulatedSignature(xml) {
  // elimina <sum1:SimulatedSignature>...</sum1:SimulatedSignature> si existiera
  return xml.replace(/<\s*sum1:SimulatedSignature[^>]*>[\s\S]*?<\s*\/\s*sum1:SimulatedSignature\s*>/gi, "");
}

function ensureRegistroAltaId(doc) {
  const reg = xpath.select("//*[local-name()='RegistroAlta']", doc)[0];
  if (!reg) throw new Error("No se encontró <sum1:RegistroAlta>");
  if (!reg.getAttribute("Id") && !reg.getAttribute("ID") && !reg.getAttribute("id")) {
    reg.setAttribute("Id", "RegistroAlta-1");
  }
  return reg.getAttribute("Id") || reg.getAttribute("ID") || reg.getAttribute("id");
}

class X509KeyInfoProvider {
  constructor(certB64) { this.certB64 = certB64; }
  getKeyInfo() {
    // xml-crypto 1.5.3 envolverá esto en <ds:KeyInfo>...</ds:KeyInfo>
    return `<X509Data><X509Certificate>${this.certB64}</X509Certificate></X509Data>`;
  }
  getKey() { return null; }
}

function buildXadesQualifyingProperties({ signatureId, signedPropsId, certDerBuffer, issuerName, serialDec }) {
  // Digest del certificado (SigningCertificate) con SHA-1 (XAdES 1.3.2)
  const certSha1B64 = sha1B64(certDerBuffer);
  const signingTime = new Date().toISOString();

  return `
<xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#${signatureId}">
  <xades:SignedProperties Id="${signedPropsId}">
    <xades:SignedSignatureProperties>
      <xades:SigningTime>${signingTime}</xades:SigningTime>
      <xades:SigningCertificate>
        <xades:Cert>
          <xades:CertDigest>
            <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="${POLICY_HASH_ALG}"/>
            <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${certSha1B64}</ds:DigestValue>
          </xades:CertDigest>
          <xades:IssuerSerial>
            <ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${issuerName}</ds:X509IssuerName>
            <ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${serialDec}</ds:X509SerialNumber>
          </xades:IssuerSerial>
        </xades:Cert>
      </xades:SigningCertificate>
      <xades:SignaturePolicyIdentifier>
        <xades:SignaturePolicyId>
          <xades:SigPolicyId>
            <xades:Identifier>${POLICY_OID}</xades:Identifier>
            <xades:Description>Política AGE</xades:Description>
            <xades:DocumentationReferences>
              <xades:DocumentationReference>${POLICY_URL}</xades:DocumentationReference>
            </xades:DocumentationReferences>
          </xades:SigPolicyId>
          <xades:SigPolicyHash>
            <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="${POLICY_HASH_ALG}"/>
            <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${POLICY_HASH_B64}</ds:DigestValue>
          </xades:SigPolicyHash>
        </xades:SignaturePolicyId>
      </xades:SignaturePolicyIdentifier>
    </xades:SignedSignatureProperties>
    <xades:SignedDataObjectProperties>
      <xades:DataObjectFormat ObjectReference="#ref-obj-registro">
        <xades:MimeType>text/xml</xades:MimeType>
        <xades:Encoding>UTF-8</xades:Encoding>
      </xades:DataObjectFormat>
    </xades:SignedDataObjectProperties>
  </xades:SignedProperties>
</xades:QualifyingProperties>
`.trim();
}

export function signXmlWithXades(xmlUnsigned) {
  const p12Path = process.env.CERT_PATH;
  const p12Pass = process.env.CERT_PASS || "";
  if (!p12Path) throw new Error("CERT_PATH no definido");

  const { privateKeyPem, certificatePem, certDerBuffer, certB64, issuerName, serialDec } =
    loadPkcs12(p12Path, p12Pass);

  // 1) limpiar marcador simulado si existe
  const xmlClean = stripSimulatedSignature(xmlUnsigned);

  // 2) asegurar Id en RegistroAlta
  const dom = new DOMParser().parseFromString(xmlClean, "text/xml");
  const regId = ensureRegistroAltaId(dom);
  const xmlPrepared = new XMLSerializer().serializeToString(dom);

  // 3) configurar SignedXml
  const sig = new SignedXml({
    idAttribute: "Id",
    signatureAlgorithm: SIG_RSA_SHA256,
    canonicalizationAlgorithm: C14N,
  });
  sig.signingKey = privateKeyPem;
  sig.keyInfoProvider = new X509KeyInfoProvider(certB64);

  // 4) referencia principal: TODO RegistroAlta (enveloped + c14n), SHA-256
  //    (usamos xpath para que xml-crypto cree URI="#<Id>" sobre el nodo)
  sig.addReference(
    "//*[local-name(.)='RegistroAlta']",
    [TR_ENVELOPED, C14N],
    DIGEST_SHA256,
    "",                    // uri (no necesario al usar xpath)
    "ref-obj-registro"     // id de la referencia
  );

  // 5) XAdES: objeto con QualifyingProperties + referencia a SignedProperties (Type XAdES)
  const signatureId = "Signature-RA-1";
  const signedPropsId = "SignedProperties-1";
  const qp = buildXadesQualifyingProperties({ signatureId, signedPropsId, certDerBuffer, issuerName, serialDec });
  sig.addObject(qp);

  sig.addReference(
    `#${signedPropsId}`,
    [C14N],
    DIGEST_SHA256,
    "http://uri.etsi.org/01903#SignedProperties"
  );

  // 6) calcular e insertar <ds:Signature> dentro de RegistroAlta
  sig.signatureId = signatureId;
  sig.computeSignature(xmlPrepared, {
    prefix: "ds",
    location: { reference: "//*[local-name(.)='RegistroAlta']", action: "append" }
  });

  return sig.getSignedXml();
}

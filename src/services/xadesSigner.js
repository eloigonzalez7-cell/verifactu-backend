// Firma XAdES-EPES para <sum1:RegistroAlta> usando PKCS#12 (.p12) del .env
// Requisitos: npm i xml-crypto @xmldom/xmldom node-forge
import fs from "fs";
import { createHash, randomUUID } from "crypto";
import { SignedXml } from "xml-crypto";
import forge from "node-forge";
import { DOMParser } from "@xmldom/xmldom";

const C14N_1_0 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const DIGEST_SHA1   = "http://www.w3.org/2000/09/xmldsig#sha1";
const TRANSFORM_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

// Política de firma (Anexo I Administración):
// OID y hash exactamente como en el ejemplo oficial.
const POLICY_OID = "urn:oid:2.16.724.1.3.1.1.2.1.9";
const POLICY_SPURI = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf";
const POLICY_SHA1_B64 = "G7roucf600+f03r/o0bAOQ6WAs0="; // del documento oficial

function ensureEnv() {
  if (!process.env.CERT_PATH || !process.env.CERT_PASS) {
    throw new Error("CERT_PATH/CERT_PASS no configurados en .env");
  }
}

function readP12() {
  const p12Der = fs.readFileSync(process.env.CERT_PATH);
  const p12Asn1 = forge.asn1.fromDer(p12Der.toString("binary"));
  return forge.pkcs12.pkcs12FromAsn1(p12Asn1, process.env.CERT_PASS);
}

function extractKeypair(p12) {
  // clave privada
  let keyBag =
    p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0] ||
    p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag]?.[0];
  if (!keyBag?.key) throw new Error("No se encontró clave privada en el .p12");
  const privateKeyPem = forge.pki.privateKeyToPem(keyBag.key);

  // certificado
  const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]?.[0];
  if (!certBag?.cert) throw new Error("No se encontró certificado en el .p12");
  const certPem = forge.pki.certificateToPem(certBag.cert);

  // cert base64 (sin cabeceras PEM)
  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(certBag.cert)).getBytes();
  const certDerBuffer = Buffer.from(certDer, "binary");
  const certB64 = certDerBuffer.toString("base64");

  // SHA-1 del certificado (para xades:SigningCertificate)
  const certSha1B64 = createHash("sha1").update(certDerBuffer).digest("base64");

  // Issuer (en minúsculas y con etiquetas cn,ou,o,c)
  const issuerAttrs = certBag.cert.issuer.attributes;
  const nameParts = [];
  const map = { CN: "cn", OU: "ou", O: "o", C: "c", L: "l", ST: "st" };
  issuerAttrs.forEach(a => {
    const key = map[a.shortName] || a.shortName?.toLowerCase() || a.name?.toLowerCase();
    if (key && a.value) nameParts.push(`${key}=${a.value}`);
  });
  const issuerName = nameParts.join(",");

  // SerialNumber decimal
  const serialHex = certBag.cert.serialNumber; // hex string
  const serialDec = BigInt("0x" + serialHex).toString(10);

  return { privateKeyPem, certPem, certB64, certSha1B64, issuerName, serialDec };
}

function isoWithTZ(now = new Date()) {
  // YYYY-MM-DDTHH:mm:ss.sss+HH:MM
  const tzMin = -now.getTimezoneOffset();
  const sign = tzMin >= 0 ? "+" : "-";
  const hh = String(Math.trunc(Math.abs(tzMin) / 60)).padStart(2, "0");
  const mm = String(Math.abs(tzMin) % 60).padStart(2, "0");
  const base = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().replace("Z", "");
  return `${base}${sign}${hh}:${mm}`;
}

/**
 * Inserta (si falta) un atributo Id en <sum1:RegistroAlta> y devuelve { xml, id }
 */
function ensureRegistroAltaId(xml) {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const nodes = doc.getElementsByTagNameNS(
    "https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/SuministroInformacion.xsd",
    "RegistroAlta"
  );

  const reg = nodes && nodes[0];
  if (!reg) throw new Error("No se encontró el nodo sum1:RegistroAlta en el XML");

  let id = reg.getAttribute("Id");
  if (!id) {
    id = "RegistroAlta-" + randomUUID();
    reg.setAttribute("Id", id);
  }
  // devolver string del documento
  return {
    id,
    xml: doc.toString()
  };
}

/**
 * Construye el bloque <ds:Object> con <xades:QualifyingProperties>
 */
function buildXadesObjectXml({ sigId, signedPropsId, signingTime, certSha1B64, issuerName, serialDec }) {
  return `
    <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:xades141="http://uri.etsi.org/01903/v1.4.1#" Target="#${sigId}">
      <xades:SignedProperties Id="${signedPropsId}">
        <xades:SignedSignatureProperties>
          <xades:SigningTime>${signingTime}</xades:SigningTime>
          <xades:SigningCertificate>
            <xades:Cert>
              <xades:CertDigest>
                <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="${DIGEST_SHA1}"/>
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
                <xades:Description/>
              </xades:SigPolicyId>
              <xades:SigPolicyHash>
                <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="${DIGEST_SHA1}"/>
                <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${POLICY_SHA1_B64}</ds:DigestValue>
              </xades:SigPolicyHash>
              <xades:SigPolicyQualifiers>
                <xades:SigPolicyQualifier>
                  <xades:SPURI>${POLICY_SPURI}</xades:SPURI>
                </xades:SigPolicyQualifier>
              </xades:SigPolicyQualifiers>
            </xades:SignaturePolicyId>
          </xades:SignaturePolicyIdentifier>
        </xades:SignedSignatureProperties>
      </xades:SignedProperties>
    </xades:QualifyingProperties>
  `.trim();
}

export function signXmlWithXades(unsignedXml) {
  ensureEnv();

  // 1) Asegurar Id en RegistroAlta
  const { id: registroId, xml: xmlWithId } = ensureRegistroAltaId(unsignedXml);

  // 2) Cargar clave/cert del .p12
  const p12 = readP12();
  const { privateKeyPem, certPem, certB64, certSha1B64, issuerName, serialDec } = extractKeypair(p12);

  // 3) Preparar XAdES QualifyingProperties
  const sigId = "xmldsig-" + randomUUID();
  const signedPropsId = `${sigId}-signedprops`;
  const xadesObjectXml = buildXadesObjectXml({
    sigId,
    signedPropsId,
    signingTime: isoWithTZ(new Date()),
    certSha1B64,
    issuerName,
    serialDec
  });

  // 4) Firmar con xml-crypto
  const sig = new SignedXml({
    canonicalizationAlgorithm: C14N_1_0,
    signatureAlgorithm: SIG_RSA_SHA256,
  });
  sig.signingKey = privateKeyPem;

  // KeyInfo con el certificado (X509Data)
  const certB64Clean = certB64.replace(/\r?\n/g, "");
  sig.keyInfoProvider = {
    getKeyInfo() {
      return `<X509Data><X509Certificate>${certB64Clean}</X509Certificate></X509Data>`;
    }
  };

  // Referencia 1: el nodo RegistroAlta (enveloped + digest SHA-256)
  sig.addReference(
    `//*[@Id='${registroId}']`,
    [TRANSFORM_ENVELOPED],
    DIGEST_SHA256
  );

  // Referencia 2: SignedProperties (c14n + digest SHA-256)
  sig.addReference(
    `//*[@Id='${signedPropsId}']`,
    [C14N_1_0],
    DIGEST_SHA256,
    // establecer URI a #signedPropsId
    `#${signedPropsId}`
  );

  // Añadir el objeto XAdES (irá dentro de <ds:Object>)
  // Nota: xml-crypto envuelve con <Object> automáticamente.
  sig.addObject(xadesObjectXml);

  // Ubicación: insertar <ds:Signature> como último hijo de RegistroAlta
  const signed = sig.computeSignature(xmlWithId, {
    location: { reference: `//*[@Id='${registroId}']`, action: "append" },
    attrs: { Id: sigId },
    prefix: "ds",
  });

  // xml-crypto no añade el atributo Type en la referencia a SignedProperties.
  // Lo agregamos post-proceso para cumplir con XAdES-EPES:
  let out = sig.getSignedXml();
  out = out.replace(
    new RegExp(`(<ds:Reference[^>]*?URI="#${signedPropsId}"[^>]*)(/?>)`),
    `$1 Type="http://uri.etsi.org/01903#SignedProperties"$2`
  );

  return out;
}

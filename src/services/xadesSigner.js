// Firma XML (enveloped) del nodo <sum1:RegistroAlta>. Si xml-crypto soporta addObject,
// inyecta además XAdES-EPES (QualifyingProperties) como <ds:Object> con la
// segunda referencia a SignedProperties (idéntico a los ejemplos de AEAT).
//
// Compatibilidad:
//  - xml-crypto 1.5.3  -> SIN addObject => firma básica (evita "sig.addObject is not a function").
//  - xml-crypto recientes -> CON addObject => firma XAdES-EPES completa.
//
// Requisitos: node-forge, @xmldom/xmldom, xml-crypto
import fs from "fs";
import { createHash, randomUUID } from "crypto";
import forge from "node-forge";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";

const NS_SUM1 = "https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/SuministroInformacion.xsd";

const C14N_1_0 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const DIGEST_SHA1   = "http://www.w3.org/2000/09/xmldsig#sha1";
const TRANSFORM_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

// Política XAdES (Anexo I) — del ejemplo oficial
const POLICY_OID = "urn:oid:2.16.724.1.3.1.1.2.1.9";
const POLICY_SPURI = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf";
const POLICY_SHA1_B64 = "G7roucf600+f03r/o0bAOQ6WAs0="; // hash SHA-1 de la política

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
  // Clave
  const keyBag =
    p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0] ||
    p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag]?.[0];
  if (!keyBag?.key) throw new Error("No se encontró clave privada en el .p12");
  const privateKeyPem = forge.pki.privateKeyToPem(keyBag.key);

  // Cert
  const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]?.[0];
  if (!certBag?.cert) throw new Error("No se encontró certificado en el .p12");
  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(certBag.cert)).getBytes();
  const certDerBuffer = Buffer.from(certDer, "binary");
  const certB64 = certDerBuffer.toString("base64");

  const certSha1B64 = createHash("sha1").update(certDerBuffer).digest("base64");

  // Issuer (formato "cn=...,ou=...,o=...,c=ES")
  const map = { CN: "cn", OU: "ou", O: "o", C: "c", L: "l", ST: "st" };
  const issuerName = certBag.cert.issuer.attributes
    .map(a => {
      const k = map[a.shortName] || a.shortName?.toLowerCase() || a.name?.toLowerCase();
      return k && a.value ? `${k}=${a.value}` : null;
    })
    .filter(Boolean)
    .join(",");

  const serialDec = BigInt("0x" + certBag.cert.serialNumber).toString(10);

  return { privateKeyPem, certB64, certSha1B64, issuerName, serialDec };
}

function isoWithTZ(now = new Date()) {
  const tzMin = -now.getTimezoneOffset();
  const sign = tzMin >= 0 ? "+" : "-";
  const hh = String(Math.trunc(Math.abs(tzMin) / 60)).padStart(2, "0");
  const mm = String(Math.abs(tzMin) % 60).padStart(2, "0");
  const base = new Date(now.getTime() - now.getTimezoneOffset() * 60000)
    .toISOString()
    .replace("Z", "");
  return `${base}${sign}${hh}:${mm}`;
}

function ensureRegistroAltaId(xml) {
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const nodes = doc.getElementsByTagNameNS(NS_SUM1, "RegistroAlta");
  const reg = nodes && nodes[0];
  if (!reg) throw new Error("No se encontró el nodo sum1:RegistroAlta");

  let id = reg.getAttribute("Id");
  if (!id) {
    id = "RegistroAlta-" + randomUUID();
    reg.setAttribute("Id", id);
  }
  return { id, xml: doc.toString() };
}

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

  // 2) Cargar clave y cert
  const p12 = readP12();
  const { privateKeyPem, certB64, certSha1B64, issuerName, serialDec } = extractKeypair(p12);

  // 3) Crear SignedXml
  const sig = new SignedXml({
    canonicalizationAlgorithm: C14N_1_0,
    signatureAlgorithm: SIG_RSA_SHA256,
  });
  sig.signingKey = privateKeyPem;

  // KeyInfo con X509 (cert base64 en una línea)
  const certB64Clean = certB64.replace(/\r?\n/g, "");
  sig.keyInfoProvider = {
    getKeyInfo() {
      return `<X509Data><X509Certificate>${certB64Clean}</X509Certificate></X509Data>`;
    }
  };

  // 4) Referencia al nodo RegistroAlta (enveloped + SHA-256)
  sig.addReference(
    `//*[@Id='${registroId}']`,
    [TRANSFORM_ENVELOPED],
    DIGEST_SHA256
  );

  // 5) (Opcional) XAdES-EPES — solo si la versión de xml-crypto admite addObject
  const hasAddObject = typeof sig.addObject === "function";
  let sigId, signedPropsId;
  if (hasAddObject) {
    sigId = "xmldsig-" + randomUUID();
    signedPropsId = `${sigId}-signedprops`;

    // Reference a SignedProperties (con C14N 1.0 + SHA-256) y URI explícito
    sig.addReference(
      `//*[@Id='${signedPropsId}']`,
      [C14N_1_0],
      DIGEST_SHA256,
      `#${signedPropsId}`
    );

    // Inyectar <ds:Object><xades:QualifyingProperties …>
    const xadesObjectXml = buildXadesObjectXml({
      sigId,
      signedPropsId,
      signingTime: isoWithTZ(new Date()),
      certSha1B64,
      issuerName,
      serialDec
    });
    sig.addObject(xadesObjectXml);
  }

  // 6) Firmar: insertar <ds:Signature> como último hijo de RegistroAlta
  const signed = sig.computeSignature(xmlWithId, {
    location: { reference: `//*[@Id='${registroId}']`, action: "append" },
    // El Id del <ds:Signature> (solo si definimos sigId)
    attrs: hasAddObject ? { Id: sigId } : undefined,
    prefix: "ds",
  });

  let out = sig.getSignedXml();

  // Si hay XAdES, forzamos el atributo Type en la Reference de SignedProperties
  if (hasAddObject) {
    out = out.replace(
      new RegExp(`(<ds:Reference[^>]*?URI="#${signedPropsId}"[^>]*)(/?>)`),
      `$1 Type="http://uri.etsi.org/01903#SignedProperties"$2`
    );
  }

  return out;
}

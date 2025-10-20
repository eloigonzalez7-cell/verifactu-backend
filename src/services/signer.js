// services/signer.js
// Firma XAdES-EPES (RSA-SHA256) sobre el nodo sum1:RegistroAlta.
// Reemplaza <sum1:SimulatedSignature> por <ds:Signature> real dentro de RegistroAlta.

import { readFileSync } from "fs";
import { createRequire } from "module";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import crypto from "crypto";
import forge from "node-forge";
import { v4 as uuidv4 } from "uuid";

const require = createRequire(import.meta.url);
const { SignedXml } = require("xml-crypto");

// Namespaces
const DS = "http://www.w3.org/2000/09/xmldsig#";
const XADES = "http://uri.etsi.org/01903/v1.3.2#";

// Política de firma de la AGE (XAdES EPES)
// OID + URL + digest SHA-1 provistos en la especificación (SigPolicyHash)  :contentReference[oaicite:3]{index=3}
const POLICY_OID = "urn:oid:2.16.724.1.3.1.1.2.1.9";
const POLICY_URI = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf";
const POLICY_HASH_ALG = "http://www.w3.org/2000/09/xmldsig#sha1";
const POLICY_HASH_B64 = "G7roucf600+f03r/o0bAOQ6WAs0=";

// Utilidad: convertir serial de cert hex -> decimal (X509SerialNumber)
function hexToDecString(hex) {
  const clean = hex.replace(/^0x/i, "");
  return BigInt("0x" + clean).toString(10);
}

// Carga PKCS#12 (.p12/.pfx) y extrae clave privada PEM y cert PEM/DER
function loadPkcs12(p12Path, passphrase) {
  const p12Der = readFileSync(p12Path);
  const p12Asn1 = forge.asn1.fromDer(p12Der.toString("binary"));
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, passphrase || "");

  // Clave privada
  const keyBags =
    p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
      forge.pki.oids.pkcs8ShroudedKeyBag
    ] ||
    p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag];

  if (!keyBags || keyBags.length === 0) {
    throw new Error("No se encontró clave privada en el PKCS#12");
  }
  const privateKey = keyBags[0].key;
  const privateKeyPem = forge.pki.privateKeyToPem(privateKey);

  // Certificado (tomamos el primero)
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[
    forge.pki.oids.certBag
  ];
  if (!certBags || certBags.length === 0) {
    throw new Error("No se encontró certificado en el PKCS#12");
  }
  const cert = certBags[0].cert;
  const certPem = forge.pki.certificateToPem(cert);

  // DER + datos de emisor/serial
  const certAsn1 = forge.pki.certificateToAsn1(cert);
  const certDer = Buffer.from(forge.asn1.toDer(certAsn1).getBytes(), "binary");
  const certB64 = certDer.toString("base64");

  const issuerAttrs = cert.issuer.attributes
    .map((a) => `${a.shortName || a.name}=${a.value}`)
    .join(", ");
  const serialHex = cert.serialNumber; // hex sin 0x
  const serialDec = hexToDecString(serialHex);

  return {
    privateKeyPem,
    certPem,
    certDer,
    certB64,
    issuerName: issuerAttrs,
    serialDec,
  };
}

// Digest base64 (alg: 'sha1'|'sha256') sobre un Buffer
function digestB64(buffer, alg) {
  return crypto.createHash(alg).update(buffer).digest("base64");
}

// Construye xades:QualifyingProperties (SignedProperties con SigningTime, SigningCertificate y SignaturePolicyIdentifier)
function buildXadesQualifyingProperties({ signatureId, signedPropsId, certDer, issuerName, serialDec }) {
  // SigningCertificate con digest del certificado (usamos SHA-1 para compatibilidad XAdES 1.3.2)
  // (La política indica SHA-1 sólo para el hash de la propia política; para la firma usamos RSA/SHA256) :contentReference[oaicite:4]{index=4}
  const certDigestB64 = digestB64(certDer, "sha1");

  const signingTime = new Date().toISOString();

  return `
  <xades:QualifyingProperties xmlns:xades="${XADES}" Target="#${signatureId}">
    <xades:SignedProperties Id="${signedPropsId}">
      <xades:SignedSignatureProperties>
        <xades:SigningTime>${signingTime}</xades:SigningTime>
        <xades:SigningCertificate>
          <xades:Cert>
            <xades:CertDigest>
              <ds:DigestMethod xmlns:ds="${DS}" Algorithm="${POLICY_HASH_ALG}"/>
              <ds:DigestValue xmlns:ds="${DS}">${certDigestB64}</ds:DigestValue>
            </xades:CertDigest>
            <xades:IssuerSerial>
              <ds:X509IssuerName xmlns:ds="${DS}">${issuerName}</ds:X509IssuerName>
              <ds:X509SerialNumber xmlns:ds="${DS}">${serialDec}</ds:X509SerialNumber>
            </xades:IssuerSerial>
          </xades:Cert>
        </xades:SigningCertificate>

        <xades:SignaturePolicyIdentifier>
          <xades:SignaturePolicyId>
            <xades:SigPolicyId>
              <xades:Identifier>${POLICY_OID}</xades:Identifier>
              <xades:Description>Política AGE</xades:Description>
              <xades:DocumentationReferences>
                <xades:DocumentationReference>${POLICY_URI}</xades:DocumentationReference>
              </xades:DocumentationReferences>
            </xades:SigPolicyId>
            <xades:SigPolicyHash>
              <ds:DigestMethod xmlns:ds="${DS}" Algorithm="${POLICY_HASH_ALG}"/>
              <ds:DigestValue xmlns:ds="${DS}">${POLICY_HASH_B64}</ds:DigestValue>
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

// Proveedor KeyInfo para xml-crypto
class X509KeyInfoProvider {
  constructor(certB64) {
    this.certB64 = certB64;
  }
  getKeyInfo() {
    // Incluimos el X509Data con el certificado (sin cadena intermedia)
    return `<ds:X509Data xmlns:ds="${DS}"><ds:X509Certificate>${this.certB64}</ds:X509Certificate></ds:X509Data>`;
  }
  getKey() {
    return null; // no requerido
  }
}

/**
 * Firma el XML (string) insertando un ds:Signature XAdES-EPES bajo sum1:RegistroAlta.
 * - Usa CERT_PATH y CERT_PASS del entorno para el PKCS#12 de pruebas (o el tuyo real).
 */
export function signXmlWithXades(xmlString) {
  const p12Path = process.env.CERT_PATH;
  const p12Pass = process.env.CERT_PASS || "";

  if (!p12Path) {
    throw new Error("CERT_PATH no configurado");
  }

  const { privateKeyPem, certDer, certB64, issuerName, serialDec } = loadPkcs12(p12Path, p12Pass);

  // Parsear XML y localizar RegistroAlta y el placeholder <sum1:SimulatedSignature>
  const dom = new DOMParser().parseFromString(xmlString, "text/xml");

  // Buscar el nodo RegistroAlta por localName para evitar líos de prefijos
  const registroAlta = dom.getElementsByTagName("sum1:RegistroAlta")[0] ||
                       Array.from(dom.getElementsByTagName("*")).find(n => n.localName === "RegistroAlta");

  if (!registroAlta) {
    throw new Error("No se encontró el nodo sum1:RegistroAlta en el XML");
  }

  // Asegurar un Id sobre RegistroAlta para referenciarlo
  let regId = registroAlta.getAttribute("Id");
  if (!regId) {
    regId = `reg-alta-${uuidv4()}`;
    registroAlta.setAttribute("Id", regId);
  }

  // Generar IDs para la firma y las SignedProperties
  const signatureId = `xmldsig-${uuidv4()}`;
  const signedPropsId = `${signatureId}-signedprops`;

  // Preparar xml-crypto
  const sig = new SignedXml({
    implicitTransformSchema: undefined,
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    idAttribute: "Id",
  });

  sig.signingKey = privateKeyPem;
  sig.keyInfoProvider = new X509KeyInfoProvider(certB64);

  // Referencia 1: al RegistroAlta (enveloped-signature)
  sig.addReference(`#${regId}`, [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
  ], "http://www.w3.org/2001/04/xmlenc#sha256", "", "", "ref-obj-registro");

  // Añadir objeto XAdES QualifyingProperties y referencia firmada a SignedProperties
  const qp = buildXadesQualifyingProperties({
    signatureId, signedPropsId, certDer, issuerName, serialDec
  });

  sig.addObject(`
    <ds:Object xmlns:ds="${DS}">
      ${qp}
    </ds:Object>
  `);

  sig.addReference(`#${signedPropsId}`, [
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
  ], "http://www.w3.org/2001/04/xmlenc#sha256",
     "http://uri.etsi.org/01903#SignedProperties");

  // Calcular firma y anexarla en RegistroAlta
  sig.computeSignature(new XMLSerializer().serializeToString(registroAlta), {
    location: {
      reference: `//*[@Id='${regId}']`,
      action: "append",
    },
    prefix: "ds",
    attrs: { Id: signatureId },
  });

  const signatureNode = sig.getSignatureXml();

  // Quitar <sum1:SimulatedSignature> si existe, y colocar ds:Signature en su lugar;
  // si no está el placeholder, la agregamos al final de RegistroAlta (válido según la espec).
  const simulated = Array.from(registroAlta.childNodes || []).find(
    (n) => n.nodeType === 1 && (n.nodeName === "sum1:SimulatedSignature" || n.localName === "SimulatedSignature")
  );

  const signatureDom = new DOMParser().parseFromString(signatureNode, "text/xml").documentElement;

  if (simulated) {
    registroAlta.replaceChild(signatureDom, simulated);
  } else {
    registroAlta.appendChild(signatureDom);
  }

  // Serializar todo el documento
  const fullXml = new XMLSerializer().serializeToString(dom);
  return fullXml;
}

// src/services/xadesSigner.js
// Firma XAdES-EPES (RSA-SHA256) sobre el nodo sum1:RegistroAlta (firma enveloped).
// Inserta <ds:Signature> dentro del registro y reemplaza <sum1:SimulatedSignature> si existe.

import { readFileSync } from "fs";
import path from "path";
import { createRequire } from "module";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import xpath from "xpath";
import crypto from "crypto";
import forge from "node-forge";

const require = createRequire(import.meta.url);
const { SignedXml } = require("xml-crypto");

const NS = {
  ds: "http://www.w3.org/2000/09/xmldsig#",
  xades: "http://uri.etsi.org/01903/v1.3.2#",
  sum1: "https://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/tike/cont/ws/SuministroInformacion.xsd",
};

// Política de firma AGE (EPES)
const POLICY_OID = "urn:oid:2.16.724.1.3.1.1.2.1.9";
const POLICY_URL = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf";
const POLICY_HASH_ALG = "http://www.w3.org/2000/09/xmldsig#sha1"; // para SigPolicyHash
const POLICY_HASH_B64 = "G7roucf600+f03r/o0bAOQ6WAs0=";          // digest SHA-1 del PDF de política

function hexToDecString(hex) {
  return BigInt("0x" + hex.replace(/^0x/i, "")).toString(10);
}
function b64Digest(buf, alg) {
  return crypto.createHash(alg).update(buf).digest("base64");
}

function loadPkcs12(p12Path, passphrase = "") {
  const abs = path.resolve(p12Path);
  const p12Der = readFileSync(abs);
  const p12Asn1 = forge.asn1.fromDer(p12Der.toString("binary"));
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, passphrase);

  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag]
    || p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag];
  if (!keyBags || !keyBags[0]?.key) throw new Error("No private key in P12");
  const privateKeyPem = forge.pki.privateKeyToPem(keyBags[0].key);

  const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag]?.[0];
  if (!certBag?.cert) throw new Error("No certificate in P12");
  const cert = certBag.cert;

  const certDer = Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), "binary");
  const certB64 = certDer.toString("base64");
  const issuerName = cert.issuer.attributes.map(a => `${a.shortName || a.name}=${a.value}`).join(", ");
  const serialDec = hexToDecString(cert.serialNumber);

  return { privateKeyPem, certDer, certB64, issuerName, serialDec };
}

function buildXadesQualifyingProperties({ signatureId, signedPropsId, certDer, issuerName, serialDec }) {
  // CertDigest de SigningCertificate con SHA-1 (XAdES 1.3.2 clásico)
  const certDigestB64 = b64Digest(certDer, "sha1");
  const signingTime = new Date().toISOString();

  return `
<xades:QualifyingProperties xmlns:xades="${NS.xades}" Target="#${signatureId}">
  <xades:SignedProperties Id="${signedPropsId}">
    <xades:SignedSignatureProperties>
      <xades:SigningTime>${signingTime}</xades:SigningTime>
      <xades:SigningCertificate>
        <xades:Cert>
          <xades:CertDigest>
            <ds:DigestMethod xmlns:ds="${NS.ds}" Algorithm="${POLICY_HASH_ALG}"/>
            <ds:DigestValue xmlns:ds="${NS.ds}">${certDigestB64}</ds:DigestValue>
          </xades:CertDigest>
          <xades:IssuerSerial>
            <ds:X509IssuerName xmlns:ds="${NS.ds}">${issuerName}</ds:X509IssuerName>
            <ds:X509SerialNumber xmlns:ds="${NS.ds}">${serialDec}</ds:X509SerialNumber>
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
            <ds:DigestMethod xmlns:ds="${NS.ds}" Algorithm="${POLICY_HASH_ALG}"/>
            <ds:DigestValue xmlns:ds="${NS.ds}">${POLICY_HASH_B64}</ds:DigestValue>
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

class X509KeyInfoProvider {
  constructor(certB64) { this.certB64 = certB64; }
  getKeyInfo() {
    return `<ds:X509Data xmlns:ds="${NS.ds}"><ds:X509Certificate>${this.certB64}</ds:X509Certificate></ds:X509Data>`;
  }
  getKey() { return null; }
}

export function signXmlWithXades(xmlUnsigned) {
  const p12Path = process.env.CERT_PATH;
  const p12Pass = process.env.CERT_PASS || "";
  if (!p12Path) throw new Error("CERT_PATH not set");

  const { privateKeyPem, certDer, certB64, issuerName, serialDec } = loadPkcs12(p12Path, p12Pass);

  const dom = new DOMParser().parseFromString(xmlUnsigned, "text/xml");
  const select = xpath.useNamespaces({ sum1: NS.sum1, ds: NS.ds });

  const registroAlta = select("//*[local-name()='RegistroAlta']", dom)?.[0];
  if (!registroAlta) throw new Error("RegistroAlta not found");

  // Garantiza Id (para referenciar el contenido del registro)
  let regId = registroAlta.getAttribute("Id");
  if (!regId) {
    regId = "RA-1";
    registroAlta.setAttribute("Id", regId);
  }

  const signatureId = "Signature-RA-1";
  const signedPropsId = "SignedProperties-1";

  const sig = new SignedXml({
    idAttribute: "Id",
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  });

  sig.signingKey = privateKeyPem;
  sig.keyInfoProvider = new X509KeyInfoProvider(certB64);

  // Referencia principal: TODO el contenido de RegistroAlta (enveloped + c14n), digest SHA-256
  sig.addReference(
    `#${regId}`,
    [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    ],
    "http://www.w3.org/2001/04/xmlenc#sha256",
    undefined,
    "ref-obj-registro"
  );

  // XAdES: Objeto + referencia a SignedProperties
  const qp = buildXadesQualifyingProperties({ signatureId, signedPropsId, certDer, issuerName, serialDec });
  sig.addObject(`<ds:Object xmlns:ds="${NS.ds}">${qp}</ds:Object>`);
  sig.addReference(
    `#${signedPropsId}`,
    ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://uri.etsi.org/01903#SignedProperties"
  );

  // Calcular firma e insertarla bajo RegistroAlta
  sig.signatureId = signatureId;
  sig.computeSignature(new XMLSerializer().serializeToString(dom), {
    prefix: "ds",
    location: { reference: "//*[local-name()='RegistroAlta']", action: "append" }
  });

  const signatureNode = new DOMParser().parseFromString(sig.getSignatureXml(), "text/xml").documentElement;

  // Reemplaza el marcador SimulatedSignature si existe
  const simulated = select("//*[local-name()='SimulatedSignature']", dom)?.[0];
  if (simulated && simulated.parentNode) {
    simulated.parentNode.replaceChild(signatureNode, simulated);
  } else {
    registroAlta.appendChild(signatureNode);
  }

  return new XMLSerializer().serializeToString(dom);
}

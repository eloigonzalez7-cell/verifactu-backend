// src/controllers/invoiceController.js
// Construye el XML, firma XAdES-EPES real y envía a AEAT.

import { buildInvoiceXml } from "../services/xmlBuilder.js";
import { sendToAEAT } from "../services/aeatClient.js";
import { signXmlWithXades } from "../services/xadesSigner.js";

export async function sendInvoice(req, res) {
  try {
    // 1) Construir XML (sin firma)
    const { xml: unsignedXml, metadata } = await buildInvoiceXml(req.body, "");

    // 2) Firmar XAdES-EPES
    let signedXml;
    try {
      signedXml = signXmlWithXades(unsignedXml);
    } catch (err) {
      console.error("❌ Signing error:", err);
      return res.status(500).json({
        status: "error",
        message: "Signing failed",
        details: err?.message || String(err),
        xmlRequest: unsignedXml
      });
    }

    // 3) Enviar a AEAT
    const aeatResponse = await sendToAEAT(signedXml);
    const httpStatus = aeatResponse.httpStatus || 200;
    const ok = httpStatus >= 200 && httpStatus < 300;

    return res.status(200).json({
      status: ok ? "success" : "warning",
      message: ok ? "✅ Sent to AEAT" : `⚠️ AEAT responded with status ${httpStatus}`,
      metadata,
      xmlRequest: signedXml,
      xmlResponse: aeatResponse
    });
  } catch (error) {
    console.error("❌ Controller error:", error);
    return res.status(500).json({
      status: "error",
      message: "Internal error building or sending invoice",
      details: error?.message || String(error)
    });
  }
}

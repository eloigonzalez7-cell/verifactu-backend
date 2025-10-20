// controllers/invoiceController.js
// Construye el XML, lo firma con XAdES-EPES real y lo envía a AEAT.

import { buildInvoiceXml } from "../services/xmlBuilder.js";
import { signXmlWithXades } from "../services/signer.js";
import { sendToAEAT } from "../services/aeatClient.js";

export async function sendInvoice(req, res) {
  try {
    const invoicePayload = req.body;

    // 1) Construir XML (sin firma, con huella calculada)
    const { xml: unsignedXml, metadata } = await buildInvoiceXml(invoicePayload, "");

    // 2) Firmar XAdES-EPES (inserta ds:Signature bajo sum1:RegistroAlta)
    let signedXml;
    try {
      signedXml = signXmlWithXades(unsignedXml);
    } catch (err) {
      console.error("❌ Error generando firma XAdES:", err);
      return res.status(500).json({
        status: "error",
        message: "No se pudo generar la firma XAdES",
        details: err.message,
        xmlRequest: unsignedXml,
      });
    }

    // 3) Enviar a AEAT
    const aeatResponse = await sendToAEAT(signedXml);
    const httpStatus = aeatResponse.httpStatus || 200;
    const isOk = httpStatus >= 200 && httpStatus < 300;

    if (isOk) {
      return res.status(200).json({
        status: "success",
        message: "✅ Invoice sent successfully to AEAT",
        metadata,
        xmlRequest: signedXml,
        xmlResponse: aeatResponse,
      });
    }

    // Devolver el detalle para diagnosticar (403 -> suele ser firma/estructura o acceso)
    return res.status(200).json({
      status: "warning",
      message: `⚠️ AEAT responded with status ${httpStatus}`,
      metadata,
      xmlRequest: signedXml,
      xmlResponse: aeatResponse,
    });
  } catch (error) {
    console.error("❌ Error en sendInvoice:", error.message);
    return res.status(500).json({
      status: "error",
      message: "Internal error building or sending invoice",
      details: error.message,
    });
  }
}

import { buildInvoiceXml } from "../services/xmlBuilder.js";
import { sendToAEAT } from "../services/aeatClient.js";
import { simulateSignature } from "../services/signer.js";

export async function sendInvoice(req, res) {
  try {
    const invoicePayload = req.body;
    const signature = simulateSignature();

    const { xml, metadata } = await buildInvoiceXml(invoicePayload, signature);

    // 🚀 Llamar a AEAT (controlado con try/catch interno)
    const aeatResponse = await sendToAEAT(xml);

    // 🧠 Analizar resultado
    const httpStatus = aeatResponse.httpStatus || 200;
    const isOk = httpStatus >= 200 && httpStatus < 300;

    if (isOk) {
      return res.status(200).json({
        status: "success",
        message: "✅ Invoice sent successfully to AEAT",
        metadata,
        xmlRequest: xml,
        xmlResponse: aeatResponse
      });
    }

    // ⚠️ Si AEAT devolvió error (403, 500, etc.)
    return res.status(200).json({
      status: "warning",
      message: `⚠️ AEAT responded with status ${httpStatus}`,
      metadata,
      xmlRequest: xml,
      xmlResponse: aeatResponse
    });

  } catch (error) {
    console.error("❌ Error en sendInvoice:", error.message);
    return res.status(500).json({
      status: "error",
      message: "Internal error building or sending invoice",
      details: error.message
    });
  }
}

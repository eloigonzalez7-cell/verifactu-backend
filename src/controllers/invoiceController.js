// Construye el XML, firma y envía a AEAT.

import { buildInvoiceXml } from "../services/xmlBuilder.js";
import { sendToAEAT } from "../services/aeatClient.js";
import { signXmlWithXades } from "../services/xadesSigner.js"; 

export async function sendInvoice(req, res) {
  try {
    const { xml: unsignedXml, metadata } = await buildInvoiceXml(req.body, "");

    let signedXml;
    try {
      signedXml = signXmlWithXades(unsignedXml);
    } catch (e) {
      return res.status(500).json({
        status: "error",
        message: "Signing failed",
        details: e?.message || String(e),
        xmlRequest: unsignedXml,
      });
    }

    const aeat = await sendToAEAT(signedXml);
    const httpStatus = aeat.httpStatus || 200;
    const ok = httpStatus >= 200 && httpStatus < 300;

    return res.status(200).json({
      status: ok ? "success" : "warning",
      message: ok ? "✅ Sent to AEAT" : `⚠️ AEAT responded with status ${httpStatus}`,
      metadata,
      xmlRequest: signedXml,
      xmlResponse: aeat,
    });
  } catch (err) {
    return res.status(500).json({
      status: "error",
      message: "Internal error building or sending invoice",
      details: err?.message || String(err),
    });
  }
}

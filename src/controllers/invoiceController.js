import { buildInvoiceXml } from "../services/xmlBuilder.js";
import { sendToAEAT } from "../services/aeatClient.js";
import { simulateSignature } from "../services/signer.js";

export async function sendInvoice(req, res, next) {
  try {
    const invoicePayload = req.body;
    const signature = simulateSignature();
    const { xml, metadata } = await buildInvoiceXml(invoicePayload, signature);
    const aeatResponse = await sendToAEAT(xml);

    res.json({
      status: "success",
      message: "Invoice validated successfully",
      metadata,
      xmlRequest: xml,
      xmlResponse: aeatResponse
    });
  } catch (error) {
    next(error);
  }
}

// services/aeatClient.js
// Envío del XML (firmado) a AEAT por HTTPS. Permite adjuntar PFX del cliente si el endpoint lo requiere.

import axios from "axios";
import https from "https";
import fs from "fs";

export async function sendToAEAT(xml) {
  if (!process.env.AEAT_ENDPOINT) {
    throw new Error("AEAT endpoint not configured");
  }

  try {
    let agent;
    try {
      if (process.env.CERT_PATH && process.env.CERT_PASS) {
        // El mismo .p12 te sirve tanto para firmar (capa app) como para MTLS si el endpoint lo necesitase.
        agent = new https.Agent({
          pfx: fs.readFileSync(process.env.CERT_PATH),
          passphrase: process.env.CERT_PASS,
          rejectUnauthorized: false,
          minVersion: "TLSv1.2",
          maxVersion: "TLSv1.2",
        });
      } else {
        // No siempre hace falta MTLS. Si AEAT/entorno no lo pide, se puede enviar sin él.
        console.warn("⚠️ CERT_PATH o CERT_PASS no definidos para HTTPS MTLS; enviando sin certificado cliente");
      }
    } catch (err) {
      console.error("❌ Error al leer certificado para HTTPS:", err.message);
    }

    const response = await axios.post(process.env.AEAT_ENDPOINT, xml, {
      httpsAgent: agent,
      headers: { "Content-Type": "text/xml; charset=utf-8" },
      timeout: 30000,
      validateStatus: () => true, // no lanzar exception automática 4xx/5xx
    });

    if (process.env.NODE_ENV !== "production") {
      console.log("📡 AEAT response status:", response.status);
      console.log("📡 AEAT response data:", response.data?.slice?.(0, 400) || response.data);
    }

    return {
      status: "ok",
      httpStatus: response.status,
      data: response.data || null,
    };
  } catch (error) {
    console.error("🔥 Error comunicando con AEAT:", error.message);
    return {
      status: "error",
      message: "Error connecting to AEAT endpoint",
      details: error.message,
    };
  }
}

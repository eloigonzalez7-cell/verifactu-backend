import axios from "axios";
import https from "https";
import fs from "fs";

export async function sendToAEAT(xml) {
  if (!process.env.AEAT_ENDPOINT) {
    throw new Error("AEAT endpoint not configured");
  }

  try {
    // 🧾 Crear agente HTTPS con certificado (si existe)
    let agent;
    try {
      if (process.env.CERT_PATH && process.env.CERT_PASS) {
        agent = new https.Agent({
          pfx: fs.readFileSync(process.env.CERT_PATH),
          passphrase: process.env.CERT_PASS,
          rejectUnauthorized: false // AEAT test env usa certificados autofirmados
        });
      } else {
        console.warn("⚠️ CERT_PATH o CERT_PASS no definidos, enviando sin certificado");
      }
    } catch (err) {
      console.error("❌ Error al leer certificado:", err.message);
    }

    // 🚀 Enviar XML firmado o sin firmar (según config)
    const response = await axios.post(process.env.AEAT_ENDPOINT, xml, {
      httpsAgent: agent,
      headers: {
        "Content-Type": "text/xml; charset=utf-8",
      },
      timeout: 30000,
      validateStatus: () => true // No lanzar excepción automática por 4xx/5xx
    });

    // 🔍 Log de depuración (solo en entorno no productivo)
    if (process.env.NODE_ENV !== "production") {
      console.log("📡 AEAT response status:", response.status);
      console.log("📡 AEAT response data:", response.data?.slice?.(0, 400) || response.data);
    }

    // ✅ Devolver respuesta estandarizada
    return {
      status: "ok",
      httpStatus: response.status,
      data: response.data || null
    };

  } catch (error) {
    console.error("🔥 Error comunicando con AEAT:", error.message);

    return {
      status: "error",
      message: "Error connecting to AEAT endpoint",
      details: error.message
    };
  }
}

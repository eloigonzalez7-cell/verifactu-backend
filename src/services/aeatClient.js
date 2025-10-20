// src/services/aeatClient.js
// Envío SOAP 1.1 a AEAT. Si hay CERT_PATH/PASS, usa mTLS.

import axios from "axios";
import https from "https";
import fs from "fs";
import path from "path";

export async function sendToAEAT(soapXml) {
  const endpoint = process.env.AEAT_ENDPOINT;
  if (!endpoint) throw new Error("AEAT_ENDPOINT not set");

  let agent;
  if (process.env.CERT_PATH && process.env.CERT_PASS) {
    try {
      agent = new https.Agent({
        pfx: fs.readFileSync(path.resolve(process.env.CERT_PATH)),
        passphrase: process.env.CERT_PASS,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.2",
        rejectUnauthorized: true
      });
    } catch (e) {
      console.warn("⚠️ Could not load client certificate:", e.message);
    }
  }

  try {
    const resp = await axios.post(endpoint, soapXml, {
      httpsAgent: agent,
      headers: {
        "Content-Type": "text/xml; charset=utf-8",
        "Accept": "text/xml",
        "SOAPAction": '""'
      },
      timeout: 30000,
      decompress: true,
      validateStatus: () => true
    });

    return {
      status: "ok",
      httpStatus: resp.status,
      data: typeof resp.data === "string" ? resp.data : String(resp.data)
    };
  } catch (err) {
    return {
      status: "error",
      httpStatus: 0,
      message: err.message
    };
  }
}

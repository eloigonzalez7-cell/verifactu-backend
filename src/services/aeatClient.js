// Cliente SOAP AEAT con certificado TLS mutuo (pfx)
import https from "https";
import axios from "axios";
import fs from "fs";
import path from "path";

const ENDPOINT = process.env.AEAT_ENDPOINT;

const agent = new https.Agent({
  pfx: fs.readFileSync(path.resolve(process.env.CERT_PATH)),
  passphrase: process.env.CERT_PASS || "",
  rejectUnauthorized: true,
  keepAlive: true,
  minVersion: "TLSv1.2",
  maxVersion: "TLSv1.2",
});

export async function sendToAEAT(xmlBody) {
  const url = ENDPOINT;
  const headers = {
    "Content-Type": "text/xml; charset=utf-8",
    "SOAPAction": "ValRegistroNoVF",
    "Accept": "text/xml",
    "User-Agent": "enviafacturas.es/1.0",
    "Connection": "keep-alive",
    "Host": new URL(url).host,
  };

  try {
    const resp = await axios.post(url, xmlBody, {
      httpsAgent: agent,
      headers,
      timeout: 30000,
      maxBodyLength: Infinity,
      validateStatus: () => true,
    });

    return {
      status: "ok",
      httpStatus: resp.status,
      data: typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data),
      headers: resp.headers,
    };
  } catch (err) {
    return {
      status: "error",
      httpStatus: err.response?.status || 0,
      data: err.response?.data || String(err.message || err),
    };
  }
}

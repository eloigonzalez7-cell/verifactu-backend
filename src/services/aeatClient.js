import axios from "axios";

export async function sendToAEAT(xml) {
  if (!process.env.AEAT_ENDPOINT) {
    throw new Error("AEAT endpoint not configured");
  }

  const { data } = await axios.post(process.env.AEAT_ENDPOINT, xml, {
    headers: { "Content-Type": "text/xml; charset=utf-8" },
    timeout: 30000
  });

  return data;
}

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 📌 Ruta correcta: ../templates/invoice-template.xml
const TEMPLATE_PATH = path.resolve(__dirname, "..", "templates", "invoice-template.xml");

function toMoney(n) {
  return Number(n).toFixed(2);
}

export async function buildInvoiceXml(payload) {
  let xml = await readFile(TEMPLATE_PATH, "utf8");

  const {
    emisor,
    receptor,
    numero,
    fechaEmision,
    descripcionOperacion,
    lineas = [],
    huellaHex, // la calculas antes de firmar
  } = payload;

  const base = lineas.reduce((acc, l) => acc + Number(l.cantidad) * Number(l.precio), 0);
  const tipoIva = Number(lineas[0]?.tipoIva ?? 21);
  const cuota = base * (tipoIva / 100);
  const total = base + cuota;

  const replacements = {
    "{{EMISOR_NOMBRE}}": emisor?.nombre ?? "",
    "{{EMISOR_NIF}}": emisor?.nif ?? "",
    "{{NUMERO}}": numero ?? "",
    "{{FECHA}}": fechaEmision ?? "",
    "{{DESCRIPCION}}": descripcionOperacion ?? "",
    "{{RECEPTOR_NOMBRE}}": receptor?.nombre ?? "",
    "{{RECEPTOR_NIF}}": receptor?.nif ?? "",
    "{{IVA}}": tipoIva.toFixed(2),
    "{{BASE}}": toMoney(base),
    "{{CUOTA}}": toMoney(cuota),
    "{{TOTAL}}": toMoney(total),
    "{{TIMESTAMP}}": new Date().toISOString(),
    "{{HUELLA}}": huellaHex ?? "",
  };

  for (const [key, val] of Object.entries(replacements)) {
    xml = xml.replaceAll(key, String(val));
  }

  // Limpieza defensiva por si queda algún marcador antiguo en un template previo
  xml = xml.replace(/<!--\s*Marcador[\s\S]*?-->/g, "");
  xml = xml.replace(/<\s*sum1:SimulatedSignature[^>]*>[\s\S]*?<\s*\/\s*sum1:SimulatedSignature\s*>/g, "");
  xml = xml.replace(/\n[ \t]*\n+/g, "\n");

  return xml;
}

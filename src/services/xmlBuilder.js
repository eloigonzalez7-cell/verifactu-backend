import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function toMoney(n) {
  return Number(n).toFixed(2);
}

export async function buildInvoiceXml(payload) {
  const tplPath = path.join(__dirname, "templates", "invoice-template.xml");
  let xml = await readFile(tplPath, "utf8");

  const {
    emisor,
    receptor,
    numero,
    fechaEmision,
    descripcionOperacion,
    lineas = [],
  } = payload;

  const base = lineas.reduce((acc, l) => acc + Number(l.cantidad) * Number(l.precio), 0);
  const tipoIva = lineas[0]?.tipoIva ?? 21;
  const cuota = base * (Number(tipoIva) / 100);
  const total = base + cuota;

  const replacements = {
    "{{EMISOR_NOMBRE}}": emisor.nombre,
    "{{EMISOR_NIF}}": emisor.nif,
    "{{NUMERO}}": numero,
    "{{FECHA}}": fechaEmision,
    "{{DESCRIPCION}}": descripcionOperacion,
    "{{RECEPTOR_NOMBRE}}": receptor.nombre,
    "{{RECEPTOR_NIF}}": receptor.nif,
    "{{IVA}}": Number(tipoIva).toFixed(2),
    "{{BASE}}": toMoney(base),
    "{{CUOTA}}": toMoney(cuota),
    "{{TOTAL}}": toMoney(total),
    "{{TIMESTAMP}}": new Date().toISOString(),
    "{{HUELLA}}": payload.huellaHex ?? "", // la huella se mete antes de firmar
  };

  for (const [key, val] of Object.entries(replacements)) {
    xml = xml.replaceAll(key, val);
  }

  // Por si queda rastro del placeholder en algún template antiguo:
  xml = xml.replace(/<!--\s*Marcador[\s\S]*?-->/g, "");
  xml = xml.replace(/<\s*sum1:SimulatedSignature\s*>[\s\S]*?<\s*\/\s*sum1:SimulatedSignature\s*>/g, "");

  return xml;
}

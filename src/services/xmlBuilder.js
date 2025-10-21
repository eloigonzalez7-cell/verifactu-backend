import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Plantilla en: /src/templates/invoice-template.xml
const TEMPLATE_PATH = path.resolve(__dirname, "..", "templates", "invoice-template.xml");

function toMoney(n) {
  return Number(n || 0).toFixed(2);
}

export async function buildInvoiceXml(payload) {
  const {
    emisor,
    receptor,
    numero,
    fechaEmision,
    descripcionOperacion,
    lineas = [],
  } = payload || {};

  if (!emisor?.nif || !emisor?.nombre) throw new Error("Emisor incompleto");
  if (!receptor?.nif || !receptor?.nombre) throw new Error("Receptor incompleto");
  if (!numero || !fechaEmision || !descripcionOperacion) throw new Error("Faltan datos de la factura");
  if (!Array.isArray(lineas) || lineas.length === 0) throw new Error("Debe incluir al menos una línea");

  const base = lineas.reduce((acc, l) => acc + Number(l.cantidad || 0) * Number(l.precio || 0), 0);
  const tipoIva = Number(lineas[0]?.tipoIva ?? 21);
  const cuota = base * (tipoIva / 100);
  const total = base + cuota;

  // Huella (hash) – no toco tu “regla” porque te está funcionando con AEAT
  const timestamp = new Date().toISOString();
  const hashSource = `${emisor.nif}${numero}${fechaEmision}F1${toMoney(cuota)}${toMoney(total)}${timestamp}`;
  const huellaHex = createHash("sha256").update(hashSource).digest("hex").toUpperCase();

  let xml = await readFile(TEMPLATE_PATH, "utf8");

  const replacements = {
    "{{EMISOR_NOMBRE}}": emisor.nombre,
    "{{EMISOR_NIF}}": emisor.nif,
    "{{NUMERO}}": numero,
    "{{FECHA}}": fechaEmision, // formato dd-mm-aaaa si ya lo pasas así
    "{{DESCRIPCION}}": descripcionOperacion,
    "{{RECEPTOR_NOMBRE}}": receptor.nombre,
    "{{RECEPTOR_NIF}}": receptor.nif,
    "{{IVA}}": toMoney(tipoIva),
    "{{BASE}}": toMoney(base),
    "{{CUOTA}}": toMoney(cuota),
    "{{TOTAL}}": toMoney(total),
    "{{TIMESTAMP}}": timestamp,
    "{{HUELLA}}": huellaHex
  };

  for (const [key, val] of Object.entries(replacements)) {
    xml = xml.replaceAll(key, String(val));
  }

  // por si quedara basura de plantillas antiguas
  xml = xml.replace(/<!--\s*Marcador[\s\S]*?-->/g, "");
  xml = xml.replace(/<\s*sum1:SimulatedSignature[^>]*>[\s\S]*?<\s*\/\s*sum1:SimulatedSignature\s*>/g, "");
  xml = xml.replace(/\n[ \t]*\n+/g, "\n");

  return {
    xml,
    metadata: {
      timestamp,
      huella: huellaHex,
      base: toMoney(base),
      cuota: toMoney(cuota),
      total: toMoney(total),
    }
  };
}

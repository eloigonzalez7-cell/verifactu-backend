import { readFile } from "fs/promises";
import { createHash } from "crypto";
import { create } from "xmlbuilder2";

const templatePath = new URL("../templates/invoice-template.xml", import.meta.url);

const PLACEHOLDERS = [
  "EMISOR_NOMBRE",
  "EMISOR_NIF",
  "NUMERO",
  "FECHA",
  "DESCRIPCION",
  "RECEPTOR_NOMBRE",
  "RECEPTOR_NIF",
  "IVA",
  "BASE",
  "CUOTA",
  "TOTAL",
  "TIMESTAMP",
  "HUELLA",
  "SIGNATURE"
];

function formatNumber(value) {
  return Number(value || 0).toFixed(2);
}

function ensureSingleVAT(lines) {
  const distinctRates = [...new Set(lines.map((line) => Number(line.tipoIva)))];
  if (distinctRates.length === 0) {
    throw new Error("No IVA rate provided in invoice lines");
  }
  if (distinctRates.length > 1) {
    console.warn("⚠️ Multiple IVA rates detected. Using the first one for simplified XML.");
  }
  return distinctRates[0];
}

export async function buildInvoiceXml(invoice, signature) {
  if (!invoice) throw new Error("Missing invoice payload");

  const {
    emisor,
    receptor,
    numero,
    fechaEmision,
    descripcionOperacion,
    lineas = []
  } = invoice;

  if (!emisor?.nif || !emisor?.nombre)
    throw new Error("Incomplete emitter information");
  if (!receptor?.nif || !receptor?.nombre)
    throw new Error("Incomplete receiver information");
  if (!numero || !fechaEmision || !descripcionOperacion)
    throw new Error("Invoice number, date and description are required");
  if (!Array.isArray(lineas) || lineas.length === 0)
    throw new Error("Invoice must contain at least one line");

  // ✅ Calcular base, cuota y total según tu payload real
  const iva = ensureSingleVAT(lineas);
  const baseTotal = lineas.reduce(
    (acc, line) => acc + (Number(line.precio || 0) * Number(line.cantidad || 1)),
    0
  );
  const quotaTotal = baseTotal * (iva / 100);
  const amountTotal = baseTotal + quotaTotal;

  // ✅ Generar hash (huella)
  const timestamp = new Date().toISOString();
  const hashSource = `${emisor.nif}${numero}${fechaEmision}F1${formatNumber(quotaTotal)}${formatNumber(amountTotal)}${timestamp}`;
  const huella = createHash("sha256").update(hashSource).digest("hex").toUpperCase();

  // ✅ Sustituir placeholders en plantilla XML
  const replacements = {
    EMISOR_NOMBRE: emisor.nombre,
    EMISOR_NIF: emisor.nif,
    NUMERO: numero,
    FECHA: fechaEmision,
    DESCRIPCION: descripcionOperacion,
    RECEPTOR_NOMBRE: receptor.nombre,
    RECEPTOR_NIF: receptor.nif,
    IVA: formatNumber(iva),
    BASE: formatNumber(baseTotal),
    CUOTA: formatNumber(quotaTotal),
    TOTAL: formatNumber(amountTotal),
    TIMESTAMP: timestamp,
    HUELLA: huella,
    SIGNATURE: signature || ""
  };

  let template = await readFile(templatePath, "utf-8");
  for (const key of PLACEHOLDERS) {
    template = template.replaceAll(`{{${key}}}`, replacements[key]);
  }

  // ✅ Generar XML sin saltos innecesarios
  const document = create(template);
  const xml = document.end({ prettyPrint: false });

  return {
    xml,
    metadata: {
      timestamp,
      huella,
      base: formatNumber(baseTotal),
      cuota: formatNumber(quotaTotal),
      total: formatNumber(amountTotal)
    }
  };
}

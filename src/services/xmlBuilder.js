// services/xmlBuilder.js
// Construye el SOAP + RegistroAlta con placeholders y huella SHA-256.
// NO firma: la firma real se inyecta luego en signer.signXmlWithXades().

import { readFile } from "fs/promises";
import { createHash } from "crypto";
import { create } from "xmlbuilder2";

const templatePath = new URL("./templates/invoice-template.xml", import.meta.url);

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
  // dejamos SIGNATURE para que el signer lo reemplace por ds:Signature
  "SIGNATURE",
];

function formatNumber(value) {
  return Number(value || 0).toFixed(2);
}

function ensureSingleVAT(lines) {
  const rates = [...new Set(lines.map((l) => Number(l.tipoIva)))];
  if (rates.length === 0) throw new Error("No IVA rate provided in invoice lines");
  if (rates.length > 1) {
    console.warn("⚠️ Multiple IVA rates detected. Using the first one for simplified XML.");
  }
  return rates[0];
}

export async function buildInvoiceXml(invoice, signature = "") {
  if (!invoice) throw new Error("Missing invoice payload");

  const {
    emisor,
    receptor,
    numero,
    fechaEmision,
    descripcionOperacion,
    lineas = [],
  } = invoice;

  if (!emisor?.nif || !emisor?.nombre) throw new Error("Incomplete emitter information");
  if (!receptor?.nif || !receptor?.nombre) throw new Error("Incomplete receiver information");
  if (!numero || !fechaEmision || !descripcionOperacion) {
    throw new Error("Invoice number, date and description are required");
  }
  if (!Array.isArray(lineas) || lineas.length === 0) {
    throw new Error("Invoice must contain at least one line");
  }

  const iva = ensureSingleVAT(lineas);
  const baseTotal = lineas.reduce(
    (acc, line) => acc + (Number(line.precio || 0) * Number(line.cantidad || 1)),
    0
  );
  const quotaTotal = baseTotal * (iva / 100);
  const amountTotal = baseTotal + quotaTotal;

  // Huella (TipoHuella 01 -> SHA-256). La especificación muestra ejemplos de valor
  // pero no fija la fórmula de concatenación en el documento aportado. Mantengo tu criterio
  // de concatenar: NIF + NumSerie + FechaExpedicion + 'F1' + CuotaTotal + ImporteTotal + Timestamp. :contentReference[oaicite:5]{index=5}
  const timestamp = new Date().toISOString();
  const hashSource = `${emisor.nif}${numero}${fechaEmision}F1${formatNumber(quotaTotal)}${formatNumber(amountTotal)}${timestamp}`;
  const huella = createHash("sha256").update(hashSource).digest("hex").toUpperCase();

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
    SIGNATURE: signature || "", // será reemplazado luego por ds:Signature real
  };

  let template = await readFile(templatePath, "utf-8");
  for (const key of PLACEHOLDERS) {
    template = template.replaceAll(`{{${key}}}`, replacements[key]);
  }

  // XML compacto (sin pretty print)
  const document = create(template);
  const xml = document.end({ prettyPrint: false });

  return {
    xml,
    metadata: {
      timestamp,
      huella,
      base: formatNumber(baseTotal),
      cuota: formatNumber(quotaTotal),
      total: formatNumber(amountTotal),
    },
  };
}

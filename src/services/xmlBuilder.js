// Construye el SOAP usando la plantilla y calcula la Huella (SHA-256).
// No firma aquí: la firma real se inserta después en signer.signXmlWithXades().

import { readFile } from "fs/promises";
import path from "path";
import { createHash } from "crypto";

const templatePath = path.resolve("src/services/templates/invoice-template.xml");

function two(n){ return String(n).padStart(2,"0"); }
function isoWithOffset(d = new Date()){
  const tz = -d.getTimezoneOffset(); // minutos respecto UTC
  const sign = tz >= 0 ? "+" : "-";
  const hh = two(Math.floor(Math.abs(tz)/60));
  const mm = two(Math.abs(tz)%60);
  return d.toISOString().replace("Z", `${sign}${hh}:${mm}`);
}
function num(v){ return Number(v || 0); }
function f2(v){ return num(v).toFixed(2); }

function ensureSingleVat(lines){
  const rates = [...new Set(lines.map(l => Number(l.tipoIva)))];
  if (rates.length === 0) throw new Error("Missing tipoIva in lines");
  if (rates.length > 1) console.warn("Multiple tipoIva detected; using the first for simplified XML");
  return rates[0];
}

export async function buildInvoiceXml(invoice, signature = "") {
  const { emisor, receptor, numero, fechaEmision, descripcionOperacion, lineas = [] } = invoice || {};
  if (!emisor?.nif || !emisor?.nombre) throw new Error("Incomplete emitter info");
  if (!receptor?.nif || !receptor?.nombre) throw new Error("Incomplete receiver info");
  if (!numero || !fechaEmision || !descripcionOperacion) throw new Error("Missing numero/fechaEmision/descripcionOperacion");
  if (!Array.isArray(lineas) || lineas.length === 0) throw new Error("Invoice must have at least one line");

  const iva = ensureSingleVat(lineas);
  const base = lineas.reduce((acc, l) => acc + num(l.cantidad) * num(l.precio), 0);
  const cuota = +(base * (iva/100));
  const total = base + cuota;

  // Timestamp con offset local
  const timestamp = isoWithOffset(new Date());

  // Huella (TipoHuella 01 -> SHA-256). Mantengo criterio simple (ajustable):
  // NIF + NumSerie + FechaExpedicion + TipoFactura(F1) + CuotaTotal + ImporteTotal + Timestamp
  const huellaSource = `${emisor.nif}${numero}${fechaEmision}F1${f2(cuota)}${f2(total)}${timestamp}`;
  const huella = createHash("sha256").update(huellaSource).digest("hex").toUpperCase();

  let xml = await readFile(templatePath, "utf-8");
  const replacements = {
    EMISOR_NOMBRE: emisor.nombre,
    EMISOR_NIF: emisor.nif,
    NUMERO: numero,
    FECHA: fechaEmision,
    DESCRIPCION: descripcionOperacion,
    RECEPTOR_NOMBRE: receptor.nombre,
    RECEPTOR_NIF: receptor.nif,
    IVA: f2(iva),
    BASE: f2(base),
    CUOTA: f2(cuota),
    TOTAL: f2(total),
    TIMESTAMP: timestamp,
    HUELLA: huella,
    SIGNATURE: signature || ""
  };
  for (const [k, v] of Object.entries(replacements)) {
    xml = xml.replaceAll(`{{${k}}}`, v);
  }

  return {
    xml,
    metadata: {
      timestamp,
      huella,
      base: f2(base),
      cuota: f2(cuota),
      total: f2(total)
    }
  };
}

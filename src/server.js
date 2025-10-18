// Ruta del archivo: ./src/server.js
import "dotenv/config";
import express from "express";
import morgan from "morgan";
import invoiceRoutes from "./routes/invoiceRoutes.js";

const app = express();

// ✅ Lista de orígenes permitidos (localhost + GitHub Pages)
const allowedOrigins = [
  "http://localhost:5173",
  "https://eloigonzalez7-cell.github.io"
];

// ✅ CORS manual (robusto y compatible con Render/Koyeb)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const isAllowed = !origin || allowedOrigins.some(o => origin.startsWith(o));

  if (isAllowed) {
    res.header("Access-Control-Allow-Origin", origin || "*");
    res.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.header("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
      return res.sendStatus(200); // Preflight OK
    }

    return next();
  }

  console.warn("❌ CORS blocked for origin:", origin);
  return res.status(403).json({
    status: "error",
    message: "CORS not allowed for this origin",
  });
});

// ✅ Middlewares
app.use(express.json({ limit: "1mb" })); // Soporte JSON
app.use(express.text({ type: ["application/xml", "text/xml", "text/plain"] })); // Soporte XML o texto
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// ✅ Ruta raíz (mensaje satisfactorio)
app.get("/api", (req, res) => {
  res.status(200).json({
    status: "ok",
    message: "🚀 VeriFactu Backend is running successfully on enviafacturas.es/api",
    environment: process.env.NODE_ENV || "development",
  });
});

// ✅ Rutas principales
app.use("/api", invoiceRoutes);

// ✅ 404 fallback
app.use((req, res) => {
  res.status(404).json({
    status: "error",
    message: "Route not found",
    path: req.originalUrl,
  });
});

// ✅ Manejador global de errores
app.use((err, req, res, next) => {
  console.error("[Error]", err.message);
  res.status(500).json({
    status: "error",
    message: err.message || "Unexpected error",
  });
});

// ✅ Inicio del servidor
const port = Number(process.env.PORT) || 8000;
app.listen(port, () => {
  console.log(`✅ Server listening on port ${port}`);
});

// Ruta del archivo: ./src/server.js
import "dotenv/config";
import express from "express";
import cors from "cors";
import morgan from "morgan";

import invoiceRoutes from "./routes/invoiceRoutes.js";

const app = express();

// ✅ Lista de orígenes permitidos (localhost + GitHub Pages)
const allowedOrigins = [
  "http://localhost:5173",
  "https://eloigonzalez7-cell.github.io",
  "https://eloigonzalez7-cell.github.io/verifactu-poc"
];

// ✅ Configuración robusta de CORS
app.use(
  cors({
    origin: (origin, callback) => {
      // Permite solicitudes sin origen (como desde Postman o curl)
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn("❌ CORS blocked for origin:", origin);
        callback(new Error("CORS not allowed for this origin"));
      }
    },
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

// ✅ Rutas principales
app.use("/api", invoiceRoutes);

// ✅ 404 fallback
app.use((req, res) => {
  res.status(404).json({ status: "error", message: "Route not found" });
});

// ✅ Manejador global de errores
app.use((err, req, res, next) => {
  const status = err.response?.status || 500;
  const message = err.response?.data || err.message || "Unexpected error";
  console.error("[Error]", message);
  res.status(status).json({
    status: "error",
    message,
    details: err.response?.data || undefined
  });
});

const port = Number(process.env.PORT) || 4000;
app.listen(port, () => {
  console.log(`✅ Server listening on port ${port}`);
});

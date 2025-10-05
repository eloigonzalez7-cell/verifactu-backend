// Ruta del archivo: ./src/server.js
import "dotenv/config";
import express from "express";
import cors from "cors";
import morgan from "morgan";

import invoiceRoutes from "./routes/invoiceRoutes.js";

const app = express();

const allowedOrigin = process.env.FRONTEND_URL;
app.use(
  cors({
    origin: allowedOrigin ? [allowedOrigin] : undefined,
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

app.use("/api", invoiceRoutes);

app.use((req, res) => {
  res.status(404).json({ status: "error", message: "Route not found" });
});

// eslint-disable-next-line no-unused-vars
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
  console.log(`Server listening on port ${port}`);
});

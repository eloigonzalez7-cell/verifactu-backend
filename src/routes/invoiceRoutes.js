import { Router } from "express";
import { sendInvoice } from "../controllers/invoiceController.js";

const router = Router();
router.post("/send-invoice", sendInvoice);
export default router;

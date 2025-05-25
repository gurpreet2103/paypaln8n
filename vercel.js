import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

const WEBHOOK_ID = process.env.WEBHOOK_ID || "WH-4HH29777WE733974A-5YJ87821XT078723U";

async function fetchCertificate(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error("Unable to fetch certificate");
  }
  return await response.text();
}

app.post("/verify", async (req, res) => {
  try {
    const {
      transmission_id,
      transmission_time,
      transmission_sig,
      cert_url,
      crc32_decimal
    } = req.body;

    const message = `${transmission_id}|${transmission_time}|${WEBHOOK_ID}|${crc32_decimal}`;
    const certificate = await fetchCertificate(cert_url);
    const signatureBuffer = Buffer.from(transmission_sig, "base64");

    const verifier = crypto.createVerify("SHA256");
    verifier.update(message);
    const isValid = verifier.verify(certificate, signatureBuffer);

    res.json({ signatureValid: isValid });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Export the Express app as a Vercel function
export default app;

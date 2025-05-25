// server.js

import express from 'express';
import crypto from 'crypto';
import fetch from 'node-fetch';

const app = express();
const PORT = process.env.PORT || 3000;

const WEBHOOK_ID = process.env.WEBHOOK_ID || "WH-4HH29777WE733974A-5YJ87821XT078723U";

app.use(express.json());

async function fetchCertificate(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error("Unable to fetch certificate");
  }
  return await response.text();
}

app.post('/api/verify', async (req, res) => {
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
    const signatureBuffer = Buffer.from(transmission_sig, 'base64');

    const verifier = crypto.createVerify('SHA256');
    verifier.update(message);

    const isValid = verifier.verify(certificate, signatureBuffer);

    res.status(200).json({ signatureValid: isValid });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}/api/verify`);
});

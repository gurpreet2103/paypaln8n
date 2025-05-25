// api/verify.js

import crypto from 'crypto';
import fetch from 'node-fetch';

const WEBHOOK_ID = process.env.WEBHOOK_ID || "WH-4HH29777WE733974A-5YJ87821XT078723U";

async function fetchCertificate(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error("Unable to fetch certificate");
  }
  return await response.text();
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
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
}

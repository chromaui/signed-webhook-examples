import express from 'express';
import jwt from 'jwt-simple';
import { createHash, timingSafeEqual } from 'crypto';

const app = express()
const port = process.env.PORT || 4321;
const secret = process.env.WEBHOOK_SECRET || '-default-secret--default-secret-';
const issuer = process.env.JWT_ISSUER || 'chromatic';

app.use(express.text());

app.post('/unsigned', (req, res) => {
  console.log(`${req.ip} -> /unsigned`);
  console.log(req.body);
  res.send('OK')
})

app.post('/signed', (req, res) => {
  console.log(`${req.ip} -> /signed`);

  let decoded;
  let expectedSha256;

  try {
    decoded = jwt.decode(req.header('X-Webhook-Signature'), secret, false, 'HS256')
    expectedSha256 = createHash('sha256').update(req.body).digest();
  } catch(err) {
    console.log(`❌ Could not decode JWT: ${err}`);
    res.status(403).send('Invalid JWT');
    return;
  }

  if(decoded.iss != issuer) {
    console.error(`❌ Incorrect issuer: ${decoded.iss}`);
    res.status(403).send('Invalid JWT issuer');
    return;
  }

  if(!timingSafeEqual(Buffer.from(decoded.sha256, 'hex'), expectedSha256)) {
    console.log('❌ Body SHA256 does not match');
    console.log(`   JWT: ${decoded.sha256}`);
    console.log(`Actual: ${expectedSha256.toString('hex')}`);
    res.status(403).send('Invalid JWT body hash');
    return;
  }

  console.log('✅ X-Webhook-Signature Matches');
  console.log('Claims:', decoded);
  console.log('Body:', req.body);
  res.send('OK');
})

app.listen(port, () => {
  console.log(`Listening at http://localhost:${port}`)
})
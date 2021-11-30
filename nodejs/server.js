import express from 'express';
import WebhookSignatureMiddleware from './middleware';

const app = express()
const port = process.env.PORT || 4321;
const secret = process.env.WEBHOOK_SECRET || '-default-secret--default-secret-';
const issuer = process.env.JWT_ISSUER || 'chromatic';

app.use(express.text());

app.use((req, _, next) => {
  console.log(`=> [${new Date()}] ${req.ip} - ${req.method} ${req.path}`);
  next();
})

app.use(WebhookSignatureMiddleware(secret, issuer));

app.post('/', (req, res) => {
  console.log('Body:', req.body);
  res.send('OK');
})

app.listen(port, () => {
  console.log(`Listening at http://localhost:${port}`)
})
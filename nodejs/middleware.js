import jwt from 'jwt-simple';
import { createHash, timingSafeEqual } from 'crypto';

export default function WebhookSignatureMiddleware (secret, issuer) {
  return (req, res, next) => {
    const header = req.header('X-Webhook-Signature')
    if(!header) {
      console.log('❌ X-Webhook-Signature header not present');
      res.status(401).send('Unauthorized');
      return;
    }

    let decoded;
    let expectedSha256;

    try {
      decoded = jwt.decode(header, secret, false, 'HS256')
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

    console.log('✅ X-Webhook-Signature Valid');

    next();
  }
}

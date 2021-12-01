import hashlib
import logging
import jwt
from werkzeug.wrappers import Request, Response

class WebhookSignatureMiddleware:
    def __init__(self, app, secret, issuer):
        self.app = app
        self.secret = secret
        self.issuer = issuer

    def __call__(self, environ, start_response):
        request = Request(environ)

        try:
            token = request.headers['X-Webhook-Signature']
            decoded_token = jwt.decode(token, self.secret, algorithms="HS256")
        except KeyError:
          logging.warn("❌ X-Webhook-Signature header not present")
          return Response(u'Unauthorized', mimetype= 'text/plain', status=401)(environ, start_response)
        except jwt.exceptions.InvalidSignatureError as err:
          logging.warn("❌ Could not decode JWT: %s", err)
          return Response(u'Invalid JWT', mimetype= 'text/plain', status=403)(environ, start_response)

        if decoded_token["iss"] != self.issuer:
          logging.warn("❌ Incorrect issuer: %s", decoded_token["iss"])
          return Response(u'Invalid JWT issuer', mimetype= 'text/plain', status=403)(environ, start_response)

        expected_hash = hashlib.sha256(request.data).hexdigest()

        if decoded_token["sha256"] != expected_hash:
          logging.warn('❌ Body SHA256 does not match')
          logging.warn("   JWT: %s", decoded_token["sha256"])
          logging.warn("Actual: %s", expected_hash)
          return Response(u'Invalid JWT body hash', mimetype= 'text/plain', status=403)(environ, start_response)

        logging.info('✅ X-Webhook-Signature Valid')
        return self.app(environ, start_response)

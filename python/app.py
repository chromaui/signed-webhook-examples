from flask import Flask, request
from middleware import WebhookSignatureMiddleware

secret = '-default-secret--default-secret-'
issuer = 'chromatic'

app = Flask(__name__)


app.wsgi_app = WebhookSignatureMiddleware(app.wsgi_app, secret, issuer)

@app.post("/")
def handler():
    return "<p>Hello, World!</p>"
require 'jwt'
require 'openssl'
require 'rack'

class WebhookSignatureMiddleware
  def initialize(app, secret, issuer, logger)
      @app = app
      @secret = secret
      @issuer = issuer
      @logger = logger
  end

  def call(env)
    request = Rack::Request.new(env)

    token = env['HTTP_X_WEBHOOK_SIGNATURE']
    unless token
      @logger.warn "❌ X-Webhook-Signature header not present"
      return [401, {}, ['Unauthorized']]
    end
    
    begin
      decoded_token = JWT.decode token, @secret, true, { algorithm: 'HS256' }
    rescue => err
      @logger.warn "❌ Could not decode JWT: #{err}"
      return [403, {}, ['Invalid JWT']]
    end
  
    claims = decoded_token[0]
  
    if claims['iss'] != @issuer
      @logger.warn "❌ Incorrect issuer: #{claims['iss']}"
      return [403, {}, ['Invalid JWT issuer']]
    end
    
    body = request.body.read
  
    expected_hash = OpenSSL::Digest::SHA256.digest(body).unpack1('H*')
  
    unless Rack::Utils.secure_compare(expected_hash, claims["sha256"])
      @logger.warn '❌ Body SHA256 does not match'
      @logger.warn "   JWT: #{claims['sha256']}"
      @logger.warn "Actual: #{expected_hash}"
      return [403, {}, ['Invalid JWT body hash']]
    end

    @logger.info '✅ X-Webhook-Signature Valid'

    request.body.rewind

    @app.call(env)
  end
end
require 'jwt'
require 'logger'
require 'openssl'
require 'sinatra'

logger = Logger.new(STDERR)

port = (ENV['PORT'] || 4321).freeze
issuer = (ENV['JWT_ISSUER'] || 'chromatic').freeze
secret = (ENV['WEBHOOK_SECRET'] || '-default-secret--default-secret-').freeze

set :port, port

post '/' do
  token = request.env['HTTP_X_WEBHOOK_SIGNATURE']
  unless token
    logger.warn "❌ X-Webhook-Signature header not present"
    halt 401
    return
  end
  
  begin
    decoded_token = JWT.decode token, secret, true, { algorithm: 'HS256' }
  rescue => err
    logger.warn "❌ Could not decode JWT: #{err}"
    halt 403, 'Invalid JWT'
    return
  end

  claims = decoded_token[0]


  if claims['iss'] != issuer
    logger.warn "❌ Incorrect issuer: #{claims['iss']}"
    halt 403, 'Invalid JWT issuer'
    return
  end
  
  body = request.body.read

  expected_hash = OpenSSL::Digest::SHA256.digest(body).unpack1('H*')

  unless Rack::Utils.secure_compare(expected_hash, claims["sha256"])
    logger.warn '❌ Body SHA256 does not match'
    logger.warn "   JWT: #{claims['sha256']}"
    logger.warn "Actual: #{expected_hash}"
    halt 403, 'Invalid JWT body hash'
    return
  end

  logger.info '✅ X-Webhook-Signature Matches'
  logger.info "Claims: #{claims}"
  logger.info "  Body: #{body}"
end
require 'logger'
require 'sinatra'

require './middleware.rb'

logger = Logger.new(STDERR)

port = (ENV['PORT'] || 4321).freeze
issuer = (ENV['JWT_ISSUER'] || 'chromatic').freeze
secret = (ENV['WEBHOOK_SECRET'] || '-default-secret--default-secret-').freeze

set :port, port

use WebhookSignatureMiddleware, secret, issuer, logger

post '/' do
  logger.info "Body: #{request.body.read}"
end
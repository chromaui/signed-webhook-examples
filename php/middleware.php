<?php
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Psr7\Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class SignedWebhookMiddleware
{
  public function __construct($secret, $issuer)
  {
    $this->key = new Key($secret, 'HS256');
    $this->issuer = $issuer;
  }

  /**
   * 
   *
   * @param  ServerRequest  $request PSR-7 request
   * @param  RequestHandler $handler PSR-15 request handler
   *
   * @return Response
   */
  public function __invoke(Request $request, RequestHandler $handler): Response
  {
    $header = $request->getHeader('x-webhook-signature');
    if(count($header) === 0) {
      error_log('❌ X-Webhook-Signature header not present');
      return makeErrorResponse(401, 'Unauthorized');
    }

    try
    {
      $decoded = JWT::decode($header[0], $this->key);
    } catch(Exception $err)
    {
      error_log('❌ Could not decode JWT: ' . $err->getMessage());
      return makeErrorResponse(403, 'Invalid JWT');
    }

    if($decoded->iss !== $this->issuer) {
      error_log('❌ Incorrect issuer: ' . $decoded->iss);
      return makeErrorResponse(403, 'Invalid JWT issuer');
    }

    $bodyHash = hash('sha256', $request->getBody()->getContents(), false);
    $request->getBody()->rewind();

    if(!hash_equals($bodyHash, $decoded->sha256)) {
      error_log('❌ Body SHA256 does not match');
      error_log('   JWT: ' . $decoded->sha256);
      error_log('Actual: ' . $bodyHash);
      return makeErrorResponse(403, 'Invalid JWT body hash');
    }

    error_log('✅ X-Webhook-Signature Valid');

    return $handler->handle($request);
  }
}


function makeErrorResponse($code, $message) {
  $response = new Response($code);
  $response->getBody()->write($message);
  return $response;
}
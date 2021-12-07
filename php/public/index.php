<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../middleware.php';

$secret = getenv('WEBHOOK_SECRET') ?: '-default-secret--default-secret-';
$issuer = getenv('JWT_ISSUER') ?: 'chromatic';

$app = AppFactory::create();

$app->add(new SignedWebhookMiddleware($secret, $issuer));

$app->post('/', function (Request $request, Response $response, $args) {
    error_log($request->getBody()->getContents());
    $response->getBody()->write('OK');
    return $response;
});

$app->run();

<?php
declare(strict_types=1);

define('BASE_PATH', __DIR__);

require_once BASE_PATH . '/config/config.php';
require_once BASE_PATH . '/config/Helpers.php';

spl_autoload_register(function (string $class): void {
    $paths = [
        BASE_PATH . '/controllers/' . $class . '.php',
        BASE_PATH . '/models/' . $class . '.php',
        BASE_PATH . '/config/' . $class . '.php',
        BASE_PATH . '/middleware/' . $class . '.php',
    ];

    foreach ($paths as $path) {
        if (is_file($path)) {
            require_once $path;
            return;
        }
    }
});

$rememberCookie = $_COOKIE[REMEMBER_COOKIE_NAME] ?? null;
$sessionLifetime = $rememberCookie ? REMEMBER_LIFETIME : SESSION_LIFETIME;
$secureCookie = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', $secureCookie ? '1' : '0');
ini_set('session.cookie_samesite', SESSION_SAMESITE);

session_set_cookie_params([
    'lifetime' => $sessionLifetime,
    'path' => '/',
    'domain' => '',
    'secure' => $secureCookie,
    'httponly' => true,
    'samesite' => SESSION_SAMESITE,
]);

session_name(SESSION_NAME);
session_start();

enforce_session_timeout();
enforce_session_fingerprint();
enforce_session_regeneration();
touch_active_session();

if (!is_logged_in() && $rememberCookie) {
    attempt_remember_login($rememberCookie);
}

$routes = require BASE_PATH . '/config/routes.php';
$rawUrl = trim((string) ($_GET['url'] ?? ''), '/');
$routeKey = $rawUrl;

if (!array_key_exists($routeKey, $routes)) {
    http_response_code(404);
    exit('Not Found');
}

$route = $routes[$routeKey];
$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));

if (!in_array($method, $route['methods'], true)) {
    http_response_code(405);
    exit('Method Not Allowed');
}

$controllerName = $route['controller'];
$action = $route['action'];

if (!preg_match('/^[A-Za-z0-9_]+$/', $controllerName) || !preg_match('/^[A-Za-z0-9_]+$/', $action)) {
    http_response_code(404);
    exit('Not Found');
}

if (!class_exists($controllerName)) {
    http_response_code(404);
    exit('Controller not found');
}

$controller = new $controllerName();

if (!method_exists($controller, $action)) {
    http_response_code(404);
    exit('Action not found');
}

call_user_func([$controller, $action]);

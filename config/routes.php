<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

return [
    '' => ['controller' => 'AuthController', 'action' => 'login', 'methods' => ['GET']],
    'auth/login' => ['controller' => 'AuthController', 'action' => 'login', 'methods' => ['GET', 'POST']],
    'auth/register' => ['controller' => 'AuthController', 'action' => 'register', 'methods' => ['GET', 'POST']],
    'auth/logout' => ['controller' => 'AuthController', 'action' => 'logout', 'methods' => ['GET']],
    'auth/profile' => ['controller' => 'AuthController', 'action' => 'profile', 'methods' => ['GET']],
    'auth/update' => ['controller' => 'AuthController', 'action' => 'update', 'methods' => ['POST']],
    'auth/delete' => ['controller' => 'AuthController', 'action' => 'delete', 'methods' => ['POST']],
];

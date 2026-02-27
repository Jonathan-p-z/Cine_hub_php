<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

return [
    '' => ['controller' => 'HomeController', 'action' => 'index', 'methods' => ['GET']],
    'home' => ['controller' => 'HomeController', 'action' => 'index', 'methods' => ['GET']],
    'films' => ['controller' => 'FilmController', 'action' => 'index', 'methods' => ['GET']],
    'films/show' => ['controller' => 'FilmController', 'action' => 'show', 'methods' => ['GET']],
    'auth/login' => ['controller' => 'AuthController', 'action' => 'login', 'methods' => ['GET', 'POST']],
    'auth/register' => ['controller' => 'AuthController', 'action' => 'register', 'methods' => ['GET', 'POST']],
    'auth/logout' => ['controller' => 'AuthController', 'action' => 'logout', 'methods' => ['GET']],
    'auth/profile' => ['controller' => 'AuthController', 'action' => 'profile', 'methods' => ['GET']],
    'auth/update' => ['controller' => 'AuthController', 'action' => 'update', 'methods' => ['POST']],
    'auth/delete' => ['controller' => 'AuthController', 'action' => 'delete', 'methods' => ['POST']],
    'reservations' => ['controller' => 'ReservationController', 'action' => 'index', 'methods' => ['GET']],
    'reservations/seats' => ['controller' => 'ReservationController', 'action' => 'seats', 'methods' => ['GET', 'POST']],
    'reservations/cancel' => ['controller' => 'ReservationController', 'action' => 'cancel', 'methods' => ['POST']],
    'admin' => ['controller' => 'AdminController', 'action' => 'index', 'methods' => ['GET']],
    'admin/films' => ['controller' => 'AdminController', 'action' => 'films', 'methods' => ['GET']],
    'admin/films/create' => ['controller' => 'AdminController', 'action' => 'filmCreate', 'methods' => ['GET', 'POST']],
    'admin/films/edit' => ['controller' => 'AdminController', 'action' => 'filmEdit', 'methods' => ['GET', 'POST']],
    'admin/films/delete' => ['controller' => 'AdminController', 'action' => 'filmDelete', 'methods' => ['POST']],
    'admin/seances' => ['controller' => 'AdminController', 'action' => 'seances', 'methods' => ['GET']],
    'admin/seances/create' => ['controller' => 'AdminController', 'action' => 'seanceCreate', 'methods' => ['GET', 'POST']],
    'admin/seances/edit' => ['controller' => 'AdminController', 'action' => 'seanceEdit', 'methods' => ['GET', 'POST']],
    'admin/seances/delete' => ['controller' => 'AdminController', 'action' => 'seanceDelete', 'methods' => ['POST']],
    'admin/users' => ['controller' => 'AdminController', 'action' => 'users', 'methods' => ['GET']],
    'admin/users/delete' => ['controller' => 'AdminController', 'action' => 'userDelete', 'methods' => ['POST']],
    'admin/reservations' => ['controller' => 'AdminController', 'action' => 'reservations', 'methods' => ['GET']],
    'admin/reservations/delete' => ['controller' => 'AdminController', 'action' => 'reservationDelete', 'methods' => ['POST']],
];

<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class AuthMiddleware
{
    public static function requireAuth(): void
    {
        if (!is_logged_in()) {
            respond_http_error(401, 'Acces refuse. Connectez-vous.');
        }
    }

    public static function requireGuest(): void
    {
        if (is_logged_in()) {
            respond_http_error(403, 'Acces refuse.');
        }
    }

    public static function requireAdmin(): void
    {
        if (!self::isAdmin()) {
            respond_http_error(403, 'Acces admin requis.');
        }
    }

    public static function isAdmin(): bool
    {
        if (!is_logged_in()) {
            return false;
        }

        $userModel = new User();
        return $userModel->isAdmin((int) current_user_id());
    }
}

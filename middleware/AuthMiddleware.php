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
            set_flash('error', 'Acces refuse. Connectez-vous.');
            redirect('index.php?url=auth/login');
        }
    }

    public static function requireGuest(): void
    {
        if (is_logged_in()) {
            redirect('index.php?url=auth/profile');
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

<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class AuthController
{
    private User $userModel;

    public function __construct()
    {
        $this->userModel = new User();
    }

    public function login(): void
    {
        AuthMiddleware::requireGuest();

        if (is_post()) {
            $security = new SecurityLog();
            $ip = get_client_ip();
            $userAgent = get_user_agent();

            if (!verify_csrf($_POST['csrf_token'] ?? null)) {
                $errors = ['Session invalide. Merci de reessayer.'];
                view('auth/login', [
                    'errors' => $errors,
                    'email' => '',
                    'flash' => get_flash(),
                ]);
                return;
            }

            $email = trim($_POST['email'] ?? '');
            $password = $_POST['password'] ?? '';
            $remember = !empty($_POST['remember']);
            $errors = [];

            if ($email !== '' && $security->tooManyLoginAttempts($email, $ip, LOGIN_ATTEMPT_LIMIT, LOGIN_ATTEMPT_WINDOW)) {
                $errors[] = 'Trop de tentatives. Merci de patienter avant de reessayer.';
            }

            if ($email === '' || $password === '') {
                $errors[] = 'Email et mot de passe requis.';
            } else {
                $user = $this->userModel->findByEmail($email);

                if (!$user || !password_verify($password, $user['password'])) {
                    $errors[] = 'Identifiants invalides.';
                }
            }

            if (empty($errors)) {
                session_regenerate_id(true);
                $_SESSION['user_id'] = (int) $user['id'];
                $_SESSION['user_name'] = $user['name'];
                set_last_activity();
                set_session_fingerprint();
                $_SESSION['last_regen'] = time();

                if ($remember) {
                    set_remember_cookie((int) $user['id'], $user['password']);
                } else {
                    clear_remember_cookie();
                }

                $security->recordLoginAttempt($email, $ip, true);
                $security->clearLoginAttempts($email, $ip);
                $security->recordSession((int) $user['id'], session_id(), $ip, $userAgent);
                $security->recordAudit((int) $user['id'], 'login_success', $ip, $userAgent, null);

                redirect('index.php?url=auth/profile');
            }

            if ($email !== '') {
                $security->recordLoginAttempt($email, $ip, false);
                $security->recordAudit(null, 'login_failed', $ip, $userAgent, $email);
            }

            view('auth/login', [
                'errors' => $errors,
                'email' => $email,
                'flash' => get_flash(),
            ]);
            return;
        }

        view('auth/login', [
            'errors' => [],
            'email' => '',
            'flash' => get_flash(),
        ]);
    }

    public function register(): void
    {
        AuthMiddleware::requireGuest();

        if (is_post()) {
            $security = new SecurityLog();
            $ip = get_client_ip();
            $userAgent = get_user_agent();

            if (!verify_csrf($_POST['csrf_token'] ?? null)) {
                $errors = ['Session invalide. Merci de reessayer.'];
                view('auth/register', [
                    'errors' => $errors,
                    'name' => '',
                    'email' => '',
                    'flash' => get_flash(),
                ]);
                return;
            }

            $name = trim($_POST['name'] ?? '');
            $email = trim($_POST['email'] ?? '');
            $password = $_POST['password'] ?? '';
            $confirm = $_POST['confirm'] ?? '';
            $errors = [];

            if ($name === '' || $email === '' || $password === '') {
                $errors[] = 'Tous les champs sont requis.';
            }

            if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $errors[] = 'Email invalide.';
            }

            if ($password !== '' && $password !== $confirm) {
                $errors[] = 'Les mots de passe ne correspondent pas.';
            }

            if ($password !== '') {
                $errors = array_merge($errors, password_strength_errors($password, $email));
            }

            if (empty($errors) && $this->userModel->findByEmail($email)) {
                $errors[] = 'Cet email est deja utilise.';
            }

            if (empty($errors)) {
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                $userId = $this->userModel->create($name, $email, $passwordHash);
                $security->recordAudit($userId, 'register', $ip, $userAgent, $email);
                set_flash('success', 'Compte cree. Vous pouvez vous connecter.');
                redirect('index.php?url=auth/login');
            }

            view('auth/register', [
                'errors' => $errors,
                'name' => $name,
                'email' => $email,
                'flash' => get_flash(),
            ]);
            return;
        }

        view('auth/register', [
            'errors' => [],
            'name' => '',
            'email' => '',
            'flash' => get_flash(),
        ]);
    }

    public function logout(): void
    {
        AuthMiddleware::requireAuth();
        $security = new SecurityLog();
        $security->recordAudit((int) current_user_id(), 'logout', get_client_ip(), get_user_agent(), null);
        $security->endSession(session_id());
        clear_remember_cookie();
        clear_auth_session();
        redirect('index.php?url=auth/login');
    }

    public function profile(): void
    {
        AuthMiddleware::requireAuth();

        $user = $this->userModel->findById((int) current_user_id());

        view('auth/profile', [
            'user' => $user,
            'flash' => get_flash(),
        ]);
    }

    public function update(): void
    {
        AuthMiddleware::requireAuth();

        $security = new SecurityLog();
        $ip = get_client_ip();
        $userAgent = get_user_agent();

        if (!is_post()) {
            redirect('index.php?url=auth/profile');
        }

        if (!verify_csrf($_POST['csrf_token'] ?? null)) {
            set_flash('error', 'Session invalide. Merci de reessayer.');
            redirect('index.php?url=auth/profile');
        }

        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm = $_POST['confirm'] ?? '';
        $errors = [];

        if ($name === '' || $email === '') {
            $errors[] = 'Nom et email requis.';
        }

        if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Email invalide.';
        }

        if ($password !== '' && $password !== $confirm) {
            $errors[] = 'Les mots de passe ne correspondent pas.';
        }

        if ($password !== '') {
            $errors = array_merge($errors, password_strength_errors($password, $email));
        }

        $existing = $this->userModel->findByEmail($email);
        if ($existing && (int) $existing['id'] !== (int) current_user_id()) {
            $errors[] = 'Cet email est deja utilise.';
        }

        if (!empty($errors)) {
            set_flash('error', implode(' ', $errors));
            redirect('index.php?url=auth/profile');
        }

        $data = [
            'name' => $name,
            'email' => $email,
        ];

        if ($password !== '') {
            $data['password'] = password_hash($password, PASSWORD_DEFAULT);
        }

        $this->userModel->update((int) current_user_id(), $data);
        $_SESSION['user_name'] = $name;
        $security->recordAudit((int) current_user_id(), 'profile_update', $ip, $userAgent, null);
        set_flash('success', 'Compte mis a jour.');
        redirect('index.php?url=auth/profile');
    }

    public function delete(): void
    {
        AuthMiddleware::requireAuth();

        $security = new SecurityLog();
        $userId = (int) current_user_id();
        $user = $this->userModel->findById($userId);
        $auditUserId = $user ? $userId : null;
        $security->recordAudit($auditUserId, 'account_delete', get_client_ip(), get_user_agent(), null);
        $security->endSession(session_id());

        if (!is_post()) {
            redirect('index.php?url=auth/profile');
        }

        if (!verify_csrf($_POST['csrf_token'] ?? null)) {
            set_flash('error', 'Session invalide. Merci de reessayer.');
            redirect('index.php?url=auth/profile');
        }

        $this->userModel->delete($userId);
        clear_remember_cookie();
        clear_auth_session();
        redirect('index.php?url=auth/login&deleted=1');
    }
}

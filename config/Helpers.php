<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function setup_error_handling(): void
{
    error_reporting(E_ALL);
    ini_set('display_errors', APP_DEBUG ? '1' : '0');
    ini_set('log_errors', '1');
    ini_set('error_log', ERROR_LOG_FILE);

    set_error_handler(function (int $severity, string $message, string $file, int $line): bool {
        if (!(error_reporting() & $severity)) {
            return false;
        }

        $exception = new ErrorException($message, 0, $severity, $file, $line);
        handle_exception($exception);
        return true;
    });

    set_exception_handler('handle_exception');

    register_shutdown_function(function (): void {
        $error = error_get_last();
        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
            $exception = new ErrorException($error['message'], 0, $error['type'], $error['file'], $error['line']);
            handle_exception($exception);
        }
    });
}

function handle_exception(Throwable $exception): void
{
    $logMessage = sprintf(
        "[%s] %s in %s:%d\n%s",
        date('c'),
        $exception->getMessage(),
        $exception->getFile(),
        $exception->getLine(),
        $exception->getTraceAsString()
    );
    error_log($logMessage);

    if (APP_DEBUG) {
        http_response_code(500);
        echo render_error_page('Erreur interne', $exception->getMessage(), $exception);
        return;
    }

    http_response_code(500);
    echo render_error_page('Erreur interne', 'Une erreur est survenue. Merci de reessayer.', null);
}

function render_error_page(string $title, string $message, ?Throwable $exception): string
{
    $details = '';
    if ($exception !== null) {
        $details = '<pre>' . e($exception->getFile() . ':' . $exception->getLine()) . "\n" . e($exception->getTraceAsString()) . '</pre>';
    }

    return '<!doctype html>'
        . '<html lang="fr"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<title>' . e($title) . '</title>'
        . '<style>body{font-family:Arial,sans-serif;margin:40px;background:#0f172a;color:#e2e8f0}h1{margin:0 0 12px}p{color:#94a3b8}pre{white-space:pre-wrap;background:#111827;padding:16px;border-radius:8px;border:1px solid #1f2937;color:#e2e8f0}</style>'
        . '</head><body><h1>' . e($title) . '</h1><p>' . e($message) . '</p>' . $details . '</body></html>';
}

function render_http_error(int $code, string $message): string
{
    $viewFile = BASE_PATH . '/views/errors/http.php';
    if (!is_file($viewFile)) {
        return render_error_page('Erreur ' . $code, $message, null);
    }

    ob_start();
    $title = 'Erreur ' . $code;
    $details = $message;
    require $viewFile;
    return (string) ob_get_clean();
}

function respond_http_error(int $code, string $message): void
{
    http_response_code($code);
    echo render_http_error($code, $message);
    exit;
}

function redirect(string $url): void
{
    header('Location: ' . $url);
    exit;
}

function view(string $path, array $data = []): void
{
    $viewFile = BASE_PATH . '/views/' . $path . '.php';

    if (!is_file($viewFile)) {
        http_response_code(404);
        exit('View not found');
    }

    extract($data, EXTR_SKIP);
    require $viewFile;
}

function is_post(): bool
{
    return ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST';
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function csrf_input(): string
{
    $token = csrf_token();
    return '<input type="hidden" name="csrf_token" value="' . e($token) . '">';
}

function verify_csrf(?string $token): bool
{
    if (empty($_SESSION['csrf_token']) || $token === null) {
        return false;
    }

    return hash_equals($_SESSION['csrf_token'], $token);
}

function password_strength_errors(string $password, ?string $email = null): array
{
    $errors = [];
    $lower = mb_strtolower($password, 'UTF-8');

    if (strlen($password) < 8) {
        $errors[] = 'Le mot de passe doit contenir au moins 8 caracteres.';
    }

    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Le mot de passe doit contenir une majuscule.';
    }

    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'Le mot de passe doit contenir une minuscule.';
    }

    if (!preg_match('/\d/', $password)) {
        $errors[] = 'Le mot de passe doit contenir un chiffre.';
    }

    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = 'Le mot de passe doit contenir un caractere special.';
    }

    if (is_blacklisted_password($lower)) {
        $errors[] = 'Le mot de passe est trop commun.';
    }

    if ($email !== null && $email !== '') {
        $parts = explode('@', $email);
        $local = mb_strtolower($parts[0] ?? '', 'UTF-8');
        if ($local !== '' && strpos($lower, $local) !== false) {
            $errors[] = 'Le mot de passe ne doit pas contenir une partie de l\'email.';
        }
    }

    return $errors;
}

function is_blacklisted_password(string $passwordLower): bool
{
    static $blacklist = null;

    if ($blacklist === null) {
        $list = require BASE_PATH . '/config/password_blacklist.php';
        $blacklist = array_map('strval', $list);
    }

    return in_array($passwordLower, $blacklist, true);
}

function get_client_ip(): string
{
    $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    if ($forwarded !== '') {
        $parts = explode(',', $forwarded);
        $ip = trim($parts[0]);
        if ($ip !== '') {
            return $ip;
        }
    }

    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function get_user_agent(): string
{
    return substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
}

function touch_active_session(): void
{
    if (!is_logged_in()) {
        return;
    }

    $security = new SecurityLog();
    $security->touchSession(session_id());
}

function set_flash(string $type, string $message): void
{
    $_SESSION['flash'] = ['type' => $type, 'message' => $message];
}

function get_flash(): ?array
{
    if (empty($_SESSION['flash'])) {
        return null;
    }

    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);
    return $flash;
}

function is_logged_in(): bool
{
    return !empty($_SESSION['user_id']);
}

function current_user_id(): ?int
{
    return is_logged_in() ? (int) $_SESSION['user_id'] : null;
}

function set_last_activity(): void
{
    $_SESSION['last_activity'] = time();
}

function set_session_fingerprint(): void
{
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $_SESSION['fingerprint'] = hash('sha256', $userAgent);
}

function enforce_session_fingerprint(): void
{
    if (!is_logged_in()) {
        return;
    }

    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $current = hash('sha256', $userAgent);

    if (empty($_SESSION['fingerprint'])) {
        $_SESSION['fingerprint'] = $current;
        return;
    }

    if (!hash_equals((string) $_SESSION['fingerprint'], $current)) {
        clear_remember_cookie();
        clear_auth_session();
        redirect('index.php?url=auth/login');
    }
}

function enforce_session_regeneration(): void
{
    if (!is_logged_in()) {
        return;
    }

    $now = time();
    $lastRegen = (int) ($_SESSION['last_regen'] ?? 0);

    if ($now - $lastRegen >= SESSION_REGEN_INTERVAL) {
        session_regenerate_id(true);
        $_SESSION['last_regen'] = $now;
    }
}

function enforce_session_timeout(): void
{
    if (!isset($_SESSION['last_activity'])) {
        $_SESSION['last_activity'] = time();
        return;
    }

    if (time() - $_SESSION['last_activity'] > SESSION_LIFETIME) {
        clear_auth_session();
        return;
    }

    $_SESSION['last_activity'] = time();
}

function clear_auth_session(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }

    session_destroy();
}

function set_remember_cookie(int $userId, string $passwordHash): void
{
    $expiry = time() + REMEMBER_LIFETIME;
    $payload = $userId . '|' . $expiry;
    $signature = hash_hmac('sha256', $payload . '|' . $passwordHash, APP_SECRET);
    $value = $payload . '|' . $signature;
    $secureCookie = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

    setcookie(REMEMBER_COOKIE_NAME, $value, [
        'expires' => $expiry,
        'path' => '/',
        'secure' => $secureCookie,
        'httponly' => true,
        'samesite' => REMEMBER_SAMESITE,
    ]);
}

function clear_remember_cookie(): void
{
    $secureCookie = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

    setcookie(REMEMBER_COOKIE_NAME, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => $secureCookie,
        'httponly' => true,
        'samesite' => REMEMBER_SAMESITE,
    ]);
}

function attempt_remember_login(string $cookieValue): void
{
    $parts = explode('|', $cookieValue);
    if (count($parts) !== 3) {
        clear_remember_cookie();
        return;
    }

    [$userId, $expiry, $signature] = $parts;

    if (!ctype_digit($userId) || !ctype_digit($expiry)) {
        clear_remember_cookie();
        return;
    }

    if ((int) $expiry < time()) {
        clear_remember_cookie();
        return;
    }

    $userModel = new User();
    $user = $userModel->findById((int) $userId);

    if (!$user) {
        clear_remember_cookie();
        return;
    }

    $payload = $userId . '|' . $expiry;
    $expected = hash_hmac('sha256', $payload . '|' . $user['password'], APP_SECRET);

    if (!hash_equals($expected, $signature)) {
        clear_remember_cookie();
        return;
    }

    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['user_name'] = $user['name'];
    $_SESSION['last_activity'] = time();
    session_regenerate_id(true);
    $_SESSION['last_regen'] = time();
    set_session_fingerprint();
    set_remember_cookie((int) $user['id'], $user['password']);

    $security = new SecurityLog();
    $security->recordSession((int) $user['id'], session_id(), get_client_ip(), get_user_agent());
    $security->recordAudit((int) $user['id'], 'login_remember', get_client_ip(), get_user_agent(), null);
}

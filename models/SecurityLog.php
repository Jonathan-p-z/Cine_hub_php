<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class SecurityLog
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function recordLoginAttempt(string $email, string $ip, bool $success): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO login_attempts (email, ip, success, attempted_at) VALUES (:email, :ip, :success, NOW())'
        );
        $stmt->execute([
            'email' => $email,
            'ip' => $ip,
            'success' => $success ? 1 : 0,
        ]);
    }

    public function tooManyLoginAttempts(string $email, string $ip, int $limit, int $windowSeconds): bool
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM login_attempts WHERE email = :email AND ip = :ip AND success = 0 AND attempted_at >= (NOW() - INTERVAL :window SECOND)'
        );
        $stmt->execute([
            'email' => $email,
            'ip' => $ip,
            'window' => $windowSeconds,
        ]);

        return (int) $stmt->fetchColumn() >= $limit;
    }

    public function clearLoginAttempts(string $email, string $ip): void
    {
        $stmt = $this->db->prepare('DELETE FROM login_attempts WHERE email = :email AND ip = :ip');
        $stmt->execute([
            'email' => $email,
            'ip' => $ip,
        ]);
    }

    public function recordAudit(?int $userId, string $action, string $ip, string $userAgent, ?string $details = null): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO audit_logs (user_id, action, ip, user_agent, details, created_at) VALUES (:user_id, :action, :ip, :user_agent, :details, NOW())'
        );
        $stmt->execute([
            'user_id' => $userId,
            'action' => $action,
            'ip' => $ip,
            'user_agent' => $userAgent,
            'details' => $details,
        ]);
    }

    public function recordSession(int $userId, string $sessionId, string $ip, string $userAgent): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO user_sessions (user_id, session_id, ip, user_agent, created_at, last_seen) VALUES (:user_id, :session_id, :ip, :user_agent, NOW(), NOW())'
        );
        $stmt->execute([
            'user_id' => $userId,
            'session_id' => $sessionId,
            'ip' => $ip,
            'user_agent' => $userAgent,
        ]);
    }

    public function touchSession(string $sessionId): void
    {
        $stmt = $this->db->prepare(
            'UPDATE user_sessions SET last_seen = NOW() WHERE session_id = :session_id'
        );
        $stmt->execute(['session_id' => $sessionId]);
    }

    public function endSession(string $sessionId): void
    {
        $stmt = $this->db->prepare('DELETE FROM user_sessions WHERE session_id = :session_id');
        $stmt->execute(['session_id' => $sessionId]);
    }
}

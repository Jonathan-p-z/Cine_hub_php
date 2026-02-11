<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class User
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function findByEmail(string $email): ?array
    {
        $stmt = $this->db->prepare('SELECT id, name, email, password, created_at FROM users WHERE email = :email');
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        return $user ?: null;
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT id, name, email, password, created_at FROM users WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $user = $stmt->fetch();

        return $user ?: null;
    }

    public function create(string $name, string $email, string $passwordHash): int
    {
        $stmt = $this->db->prepare('INSERT INTO users (name, email, password, created_at) VALUES (:name, :email, :password, NOW())');
        $stmt->execute([
            'name' => $name,
            'email' => $email,
            'password' => $passwordHash,
        ]);

        return (int) $this->db->lastInsertId();
    }

    public function update(int $id, array $data): bool
    {
        $fields = [];
        $params = ['id' => $id];

        if (isset($data['name'])) {
            $fields[] = 'name = :name';
            $params['name'] = $data['name'];
        }

        if (isset($data['email'])) {
            $fields[] = 'email = :email';
            $params['email'] = $data['email'];
        }

        if (isset($data['password'])) {
            $fields[] = 'password = :password';
            $params['password'] = $data['password'];
        }

        if (empty($fields)) {
            return false;
        }

        $sql = 'UPDATE users SET ' . implode(', ', $fields) . ' WHERE id = :id';
        $stmt = $this->db->prepare($sql);

        return $stmt->execute($params);
    }

    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM users WHERE id = :id');
        return $stmt->execute(['id' => $id]);
    }

    public function isAdmin(int $id): bool
    {
        $stmt = $this->db->prepare(
            'SELECT r.name FROM roles r INNER JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = :id'
        );
        $stmt->execute(['id' => $id]);
        $roles = $stmt->fetchAll(PDO::FETCH_COLUMN);

        return in_array('admin', $roles, true);
    }
}

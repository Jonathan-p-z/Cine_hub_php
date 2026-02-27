<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class Seance
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT s.id, s.film_id, s.salle_id, s.starts_at, s.price,
                    sa.name AS salle, sa.capacity,
                    f.title AS film_title
             FROM seances s
             INNER JOIN salles sa ON sa.id = s.salle_id
             INNER JOIN films f ON f.id = s.film_id
             WHERE s.id = :id'
        );
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function findAllWithFilm(): array
    {
        $stmt = $this->db->prepare(
            'SELECT s.id, s.starts_at, s.price, sa.name AS salle, f.title AS film_title,
                    sa.capacity,
                    COALESCE(COUNT(rs.id), 0) AS reserved
             FROM seances s
             INNER JOIN salles sa ON sa.id = s.salle_id
             INNER JOIN films f ON f.id = s.film_id
             LEFT JOIN reservation_seats rs ON rs.seance_id = s.id
             GROUP BY s.id, s.starts_at, s.price, sa.name, f.title, sa.capacity
             ORDER BY s.starts_at DESC'
        );
        $stmt->execute();

        return $stmt->fetchAll();
    }

    public function findByFilmId(int $filmId): array
    {
        $stmt = $this->db->prepare(
            'SELECT s.id, s.starts_at, s.price, sa.name AS salle, sa.capacity,
                    COALESCE(COUNT(rs.id), 0) AS reserved
             FROM seances s
             INNER JOIN salles sa ON sa.id = s.salle_id
             LEFT JOIN reservation_seats rs ON rs.seance_id = s.id
             WHERE s.film_id = :film_id
             GROUP BY s.id, s.starts_at, s.price, sa.name, sa.capacity
             ORDER BY s.starts_at'
        );
        $stmt->execute(['film_id' => $filmId]);

        return $stmt->fetchAll();
    }

    public function create(int $filmId, int $salleId, string $startsAt, float $price): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO seances (film_id, salle_id, starts_at, price) VALUES (:film_id, :salle_id, :starts_at, :price)'
        );
        $stmt->execute([
            'film_id' => $filmId,
            'salle_id' => $salleId,
            'starts_at' => $startsAt,
            'price' => $price,
        ]);

        return (int) $this->db->lastInsertId();
    }

    public function update(int $id, array $data): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE seances SET film_id = :film_id, salle_id = :salle_id, starts_at = :starts_at, price = :price WHERE id = :id'
        );

        return $stmt->execute([
            'film_id' => $data['film_id'],
            'salle_id' => $data['salle_id'],
            'starts_at' => $data['starts_at'],
            'price' => $data['price'],
            'id' => $id,
        ]);
    }

    public function delete(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM seances WHERE id = :id');
        return $stmt->execute(['id' => $id]);
    }

    public function findAllSalles(): array
    {
        $stmt = $this->db->prepare('SELECT id, name, capacity FROM salles ORDER BY name');
        $stmt->execute();

        return $stmt->fetchAll();
    }
}

<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class Reservation
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function findByUser(int $userId): array
    {
        $stmt = $this->db->prepare(
            'SELECT r.id, r.created_at, r.seance_id,
                    s.starts_at, s.price, sa.name AS salle,
                    f.id AS film_id, f.title AS film_title,
                    COUNT(rs.id) AS seats_count
             FROM reservations r
             INNER JOIN seances s ON s.id = r.seance_id
             INNER JOIN salles sa ON sa.id = s.salle_id
             INNER JOIN films f ON f.id = s.film_id
             INNER JOIN reservation_seats rs ON rs.reservation_id = r.id
             WHERE r.user_id = :user_id
             GROUP BY r.id, r.created_at, r.seance_id, s.starts_at, s.price, sa.name, f.id, f.title
             ORDER BY r.created_at DESC'
        );
        $stmt->execute(['user_id' => $userId]);

        return $stmt->fetchAll();
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT r.id, r.user_id, r.seance_id, r.created_at
             FROM reservations r
             WHERE r.id = :id'
        );
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();

        return $row ?: null;
    }

    public function findAll(): array
    {
        $stmt = $this->db->prepare(
            'SELECT r.id, r.created_at, u.name AS user_name, u.email AS user_email,
                    f.title AS film_title, s.starts_at, sa.name AS salle,
                    COUNT(rs.id) AS seats_count, s.price
             FROM reservations r
             INNER JOIN users u ON u.id = r.user_id
             INNER JOIN seances s ON s.id = r.seance_id
             INNER JOIN salles sa ON sa.id = s.salle_id
             INNER JOIN films f ON f.id = s.film_id
             INNER JOIN reservation_seats rs ON rs.reservation_id = r.id
             GROUP BY r.id, r.created_at, u.name, u.email, f.title, s.starts_at, sa.name, s.price
             ORDER BY r.created_at DESC'
        );
        $stmt->execute();

        return $stmt->fetchAll();
    }

    public function seatsTaken(int $seanceId): array
    {
        $stmt = $this->db->prepare(
            'SELECT seat_row, seat_col FROM reservation_seats WHERE seance_id = :seance_id'
        );
        $stmt->execute(['seance_id' => $seanceId]);

        return $stmt->fetchAll();
    }

    public function countReservedSeats(int $seanceId): int
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM reservation_seats WHERE seance_id = :seance_id'
        );
        $stmt->execute(['seance_id' => $seanceId]);

        return (int) $stmt->fetchColumn();
    }

    public function create(int $userId, int $seanceId, array $seats): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO reservations (user_id, seance_id) VALUES (:user_id, :seance_id)'
        );
        $stmt->execute(['user_id' => $userId, 'seance_id' => $seanceId]);
        $reservationId = (int) $this->db->lastInsertId();

        $seatStmt = $this->db->prepare(
            'INSERT INTO reservation_seats (reservation_id, seance_id, seat_row, seat_col) VALUES (:reservation_id, :seance_id, :seat_row, :seat_col)'
        );

        foreach ($seats as $seat) {
            $seatStmt->execute([
                'reservation_id' => $reservationId,
                'seance_id' => $seanceId,
                'seat_row' => $seat['row'],
                'seat_col' => $seat['col'],
            ]);
        }

        return $reservationId;
    }

    public function cancel(int $id, int $userId): bool
    {
        $stmt = $this->db->prepare(
            'DELETE FROM reservations WHERE id = :id AND user_id = :user_id'
        );

        return $stmt->execute(['id' => $id, 'user_id' => $userId]);
    }

    public function deleteById(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM reservations WHERE id = :id');
        return $stmt->execute(['id' => $id]);
    }

    public function seatsByReservation(int $reservationId): array
    {
        $stmt = $this->db->prepare(
            'SELECT seat_row, seat_col FROM reservation_seats WHERE reservation_id = :id ORDER BY seat_row, seat_col'
        );
        $stmt->execute(['id' => $reservationId]);

        return $stmt->fetchAll();
    }
}

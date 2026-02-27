<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class Film
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getInstance();
    }

    public function findAll(int $limit = 0, ?int $genreId = null): array
    {
        $where = '';
        $params = [];

        if ($genreId !== null) {
            $where = ' WHERE f.id IN (SELECT film_id FROM film_genres WHERE genre_id = :genre_id)';
            $params['genre_id'] = $genreId;
        }

        $sql = 'SELECT f.id, f.title, f.director, f.duration, f.release_year, f.poster_url,
                       GROUP_CONCAT(g.name ORDER BY g.name SEPARATOR \', \') AS genres
                FROM films f
                LEFT JOIN film_genres fg ON fg.film_id = f.id
                LEFT JOIN genres g ON g.id = fg.genre_id'
             . $where
             . ' GROUP BY f.id ORDER BY f.created_at DESC';

        if ($limit > 0) {
            $sql .= ' LIMIT ' . $limit;
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        return $stmt->fetchAll();
    }

    public function findFeatured(): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT f.id, f.title, f.synopsis, f.director, f.duration, f.release_year, f.poster_url,
                    GROUP_CONCAT(g.name ORDER BY g.name SEPARATOR \', \') AS genres
             FROM films f
             LEFT JOIN film_genres fg ON fg.film_id = f.id
             LEFT JOIN genres g ON g.id = fg.genre_id
             WHERE f.featured = 1
             GROUP BY f.id
             LIMIT 1'
        );
        $stmt->execute();
        $film = $stmt->fetch();

        return $film ?: null;
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT f.id, f.title, f.synopsis, f.director, f.duration, f.release_year, f.poster_url,
                    GROUP_CONCAT(g.name ORDER BY g.name SEPARATOR \', \') AS genres
             FROM films f
             LEFT JOIN film_genres fg ON fg.film_id = f.id
             LEFT JOIN genres g ON g.id = fg.genre_id
             WHERE f.id = :id
             GROUP BY f.id'
        );
        $stmt->execute(['id' => $id]);
        $film = $stmt->fetch();

        return $film ?: null;
    }

    public function findSeances(int $filmId): array
    {
        $stmt = $this->db->prepare(
            'SELECT s.id, s.starts_at, s.price, sa.name AS salle, sa.capacity,
                    sa.capacity - COALESCE(COUNT(rs.id), 0) AS available
             FROM seances s
             INNER JOIN salles sa ON sa.id = s.salle_id
             LEFT JOIN reservation_seats rs ON rs.seance_id = s.id
             WHERE s.film_id = :film_id AND s.starts_at >= NOW()
             GROUP BY s.id, s.starts_at, s.price, sa.name, sa.capacity
             ORDER BY s.starts_at'
        );
        $stmt->execute(['film_id' => $filmId]);

        return $stmt->fetchAll();
    }

    public function allGenres(): array
    {
        $stmt = $this->db->prepare('SELECT id, name FROM genres ORDER BY name');
        $stmt->execute();

        return $stmt->fetchAll();
    }

    public function createFilm(string $title, string $synopsis, string $director, int $duration, int $releaseYear, ?string $posterUrl, int $featured): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO films (title, synopsis, director, duration, release_year, poster_url, featured) VALUES (:title, :synopsis, :director, :duration, :release_year, :poster_url, :featured)'
        );
        $stmt->execute([
            'title' => $title,
            'synopsis' => $synopsis,
            'director' => $director,
            'duration' => $duration,
            'release_year' => $releaseYear,
            'poster_url' => $posterUrl,
            'featured' => $featured,
        ]);

        return (int) $this->db->lastInsertId();
    }

    public function updateFilm(int $id, array $data): bool
    {
        $stmt = $this->db->prepare(
            'UPDATE films SET title = :title, synopsis = :synopsis, director = :director,
             duration = :duration, release_year = :release_year, poster_url = :poster_url,
             featured = :featured WHERE id = :id'
        );

        return $stmt->execute([
            'title' => $data['title'],
            'synopsis' => $data['synopsis'],
            'director' => $data['director'],
            'duration' => $data['duration'],
            'release_year' => $data['release_year'],
            'poster_url' => $data['poster_url'],
            'featured' => $data['featured'],
            'id' => $id,
        ]);
    }

    public function deleteFilm(int $id): bool
    {
        $stmt = $this->db->prepare('DELETE FROM films WHERE id = :id');
        return $stmt->execute(['id' => $id]);
    }

    public function addGenre(int $filmId, int $genreId): void
    {
        $stmt = $this->db->prepare(
            'INSERT IGNORE INTO film_genres (film_id, genre_id) VALUES (:film_id, :genre_id)'
        );
        $stmt->execute(['film_id' => $filmId, 'genre_id' => $genreId]);
    }

    public function removeGenres(int $filmId): void
    {
        $stmt = $this->db->prepare('DELETE FROM film_genres WHERE film_id = :film_id');
        $stmt->execute(['film_id' => $filmId]);
    }
}

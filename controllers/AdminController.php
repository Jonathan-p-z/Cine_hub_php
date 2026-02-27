<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class AdminController
{
    private Film $filmModel;
    private Seance $seanceModel;
    private User $userModel;
    private Reservation $reservationModel;

    public function __construct()
    {
        $this->filmModel = new Film();
        $this->seanceModel = new Seance();
        $this->userModel = new User();
        $this->reservationModel = new Reservation();
    }

    public function index(): void
    {
        AuthMiddleware::requireAdmin();

        $db = Database::getInstance();

        $films = (int) $db->query('SELECT COUNT(*) FROM films')->fetchColumn();
        $seances = (int) $db->query('SELECT COUNT(*) FROM seances WHERE starts_at >= NOW()')->fetchColumn();
        $users = (int) $db->query('SELECT COUNT(*) FROM users')->fetchColumn();
        $reservations = (int) $db->query('SELECT COUNT(*) FROM reservations')->fetchColumn();

        view('admin/dashboard', [
            'stats' => compact('films', 'seances', 'users', 'reservations'),
            'flash' => get_flash(),
        ]);
    }

    public function films(): void
    {
        AuthMiddleware::requireAdmin();

        $films = $this->filmModel->findAll();

        view('admin/films/index', [
            'films' => $films,
            'flash' => get_flash(),
        ]);
    }

    public function filmCreate(): void
    {
        AuthMiddleware::requireAdmin();

        $genres = $this->filmModel->allGenres();
        $errors = [];

        if (is_post()) {
            if (!verify_csrf($_POST['csrf_token'] ?? null)) {
                $errors[] = 'Session invalide.';
            } else {
                $title = trim($_POST['title'] ?? '');
                $synopsis = trim($_POST['synopsis'] ?? '');
                $director = trim($_POST['director'] ?? '');
                $duration = (int) ($_POST['duration'] ?? 0);
                $releaseYear = (int) ($_POST['release_year'] ?? 0);
                $posterUrl = trim($_POST['poster_url'] ?? '') ?: null;
                $featured = !empty($_POST['featured']) ? 1 : 0;
                $selectedGenres = $_POST['genres'] ?? [];

                if ($title === '' || $synopsis === '' || $director === '') {
                    $errors[] = 'Titre, synopsis et realisateur sont requis.';
                }
                if ($duration <= 0) {
                    $errors[] = 'Duree invalide.';
                }
                if ($releaseYear <= 0) {
                    $errors[] = 'Annee de sortie invalide.';
                }

                if (empty($errors)) {
                    $filmId = $this->filmModel->createFilm($title, $synopsis, $director, $duration, $releaseYear, $posterUrl, $featured);

                    foreach ($selectedGenres as $genreId) {
                        $this->filmModel->addGenre($filmId, (int) $genreId);
                    }

                    set_flash('success', 'Film ajoute.');
                    redirect('index.php?url=admin/films');
                }
            }
        }

        view('admin/films/create', [
            'genres' => $genres,
            'errors' => $errors,
            'old' => $_POST,
        ]);
    }

    public function filmEdit(): void
    {
        AuthMiddleware::requireAdmin();

        $id = isset($_GET['id']) && ctype_digit($_GET['id']) ? (int) $_GET['id'] : 0;

        if ($id === 0) {
            redirect('index.php?url=admin/films');
        }

        $film = $this->filmModel->findById($id);

        if ($film === null) {
            respond_http_error(404, 'Film introuvable.');
        }

        $genres = $this->filmModel->allGenres();
        $errors = [];

        $db = Database::getInstance();
        $currentGenreStmt = $db->prepare('SELECT genre_id FROM film_genres WHERE film_id = :id');
        $currentGenreStmt->execute(['id' => $id]);
        $currentGenres = $currentGenreStmt->fetchAll(PDO::FETCH_COLUMN);

        if (is_post()) {
            if (!verify_csrf($_POST['csrf_token'] ?? null)) {
                $errors[] = 'Session invalide.';
            } else {
                $title = trim($_POST['title'] ?? '');
                $synopsis = trim($_POST['synopsis'] ?? '');
                $director = trim($_POST['director'] ?? '');
                $duration = (int) ($_POST['duration'] ?? 0);
                $releaseYear = (int) ($_POST['release_year'] ?? 0);
                $posterUrl = trim($_POST['poster_url'] ?? '') ?: null;
                $featured = !empty($_POST['featured']) ? 1 : 0;
                $selectedGenres = $_POST['genres'] ?? [];

                if ($title === '' || $synopsis === '' || $director === '') {
                    $errors[] = 'Titre, synopsis et realisateur sont requis.';
                }
                if ($duration <= 0) {
                    $errors[] = 'Duree invalide.';
                }
                if ($releaseYear <= 0) {
                    $errors[] = 'Annee de sortie invalide.';
                }

                if (empty($errors)) {
                    $this->filmModel->updateFilm($id, [
                        'title' => $title,
                        'synopsis' => $synopsis,
                        'director' => $director,
                        'duration' => $duration,
                        'release_year' => $releaseYear,
                        'poster_url' => $posterUrl,
                        'featured' => $featured,
                    ]);

                    $this->filmModel->removeGenres($id);

                    foreach ($selectedGenres as $genreId) {
                        $this->filmModel->addGenre($id, (int) $genreId);
                    }

                    set_flash('success', 'Film modifie.');
                    redirect('index.php?url=admin/films');
                }

                $currentGenres = array_map('intval', $selectedGenres);
            }
        }

        view('admin/films/edit', [
            'film' => $film,
            'genres' => $genres,
            'currentGenres' => array_map('intval', $currentGenres),
            'errors' => $errors,
        ]);
    }

    public function filmDelete(): void
    {
        AuthMiddleware::requireAdmin();

        if (!is_post()) {
            redirect('index.php?url=admin/films');
        }

        if (!verify_csrf($_POST['csrf_token'] ?? null)) {
            set_flash('error', 'Session invalide.');
            redirect('index.php?url=admin/films');
        }

        $id = isset($_POST['id']) && ctype_digit($_POST['id']) ? (int) $_POST['id'] : 0;

        if ($id === 0) {
            redirect('index.php?url=admin/films');
        }

        $this->filmModel->deleteFilm($id);
        set_flash('success', 'Film supprime.');
        redirect('index.php?url=admin/films');
    }

    public function seances(): void
    {
        AuthMiddleware::requireAdmin();

        $seances = $this->seanceModel->findAllWithFilm();

        view('admin/seances/index', [
            'seances' => $seances,
            'flash' => get_flash(),
        ]);
    }

    public function seanceCreate(): void
    {
        AuthMiddleware::requireAdmin();

        $films = $this->filmModel->findAll();
        $salles = $this->seanceModel->findAllSalles();
        $errors = [];

        if (is_post()) {
            if (!verify_csrf($_POST['csrf_token'] ?? null)) {
                $errors[] = 'Session invalide.';
            } else {
                $filmId = isset($_POST['film_id']) && ctype_digit($_POST['film_id']) ? (int) $_POST['film_id'] : 0;
                $salleId = isset($_POST['salle_id']) && ctype_digit($_POST['salle_id']) ? (int) $_POST['salle_id'] : 0;
                $startsAt = trim($_POST['starts_at'] ?? '');
                $price = (float) str_replace(',', '.', $_POST['price'] ?? '0');

                if ($filmId === 0) {
                    $errors[] = 'Film invalide.';
                }
                if ($salleId === 0) {
                    $errors[] = 'Salle invalide.';
                }
                if ($startsAt === '' || strtotime($startsAt) === false) {
                    $errors[] = 'Date/heure invalide.';
                }
                if ($price <= 0) {
                    $errors[] = 'Prix invalide.';
                }

                if (empty($errors)) {
                    $this->seanceModel->create($filmId, $salleId, $startsAt, $price);
                    set_flash('success', 'Seance ajoutee.');
                    redirect('index.php?url=admin/seances');
                }
            }
        }

        view('admin/seances/create', [
            'films' => $films,
            'salles' => $salles,
            'errors' => $errors,
            'old' => $_POST,
        ]);
    }

    public function seanceEdit(): void
    {
        AuthMiddleware::requireAdmin();

        $id = isset($_GET['id']) && ctype_digit($_GET['id']) ? (int) $_GET['id'] : 0;

        if ($id === 0) {
            redirect('index.php?url=admin/seances');
        }

        $seance = $this->seanceModel->findById($id);

        if ($seance === null) {
            respond_http_error(404, 'Seance introuvable.');
        }

        $films = $this->filmModel->findAll();
        $salles = $this->seanceModel->findAllSalles();
        $errors = [];

        if (is_post()) {
            if (!verify_csrf($_POST['csrf_token'] ?? null)) {
                $errors[] = 'Session invalide.';
            } else {
                $filmId = isset($_POST['film_id']) && ctype_digit($_POST['film_id']) ? (int) $_POST['film_id'] : 0;
                $salleId = isset($_POST['salle_id']) && ctype_digit($_POST['salle_id']) ? (int) $_POST['salle_id'] : 0;
                $startsAt = trim($_POST['starts_at'] ?? '');
                $price = (float) str_replace(',', '.', $_POST['price'] ?? '0');

                if ($filmId === 0) {
                    $errors[] = 'Film invalide.';
                }
                if ($salleId === 0) {
                    $errors[] = 'Salle invalide.';
                }
                if ($startsAt === '' || strtotime($startsAt) === false) {
                    $errors[] = 'Date/heure invalide.';
                }
                if ($price <= 0) {
                    $errors[] = 'Prix invalide.';
                }

                if (empty($errors)) {
                    $this->seanceModel->update($id, [
                        'film_id' => $filmId,
                        'salle_id' => $salleId,
                        'starts_at' => $startsAt,
                        'price' => $price,
                    ]);
                    set_flash('success', 'Seance modifiee.');
                    redirect('index.php?url=admin/seances');
                }
            }
        }

        view('admin/seances/edit', [
            'seance' => $seance,
            'films' => $films,
            'salles' => $salles,
            'errors' => $errors,
        ]);
    }

    public function seanceDelete(): void
    {
        AuthMiddleware::requireAdmin();

        if (!is_post()) {
            redirect('index.php?url=admin/seances');
        }

        if (!verify_csrf($_POST['csrf_token'] ?? null)) {
            set_flash('error', 'Session invalide.');
            redirect('index.php?url=admin/seances');
        }

        $id = isset($_POST['id']) && ctype_digit($_POST['id']) ? (int) $_POST['id'] : 0;

        if ($id === 0) {
            redirect('index.php?url=admin/seances');
        }

        $this->seanceModel->delete($id);
        set_flash('success', 'Seance supprimee.');
        redirect('index.php?url=admin/seances');
    }

    public function users(): void
    {
        AuthMiddleware::requireAdmin();

        $db = Database::getInstance();
        $stmt = $db->prepare(
            'SELECT u.id, u.name, u.email, u.created_at,
                    GROUP_CONCAT(r.name SEPARATOR \', \') AS roles
             FROM users u
             LEFT JOIN user_roles ur ON ur.user_id = u.id
             LEFT JOIN roles r ON r.id = ur.role_id
             GROUP BY u.id, u.name, u.email, u.created_at
             ORDER BY u.created_at DESC'
        );
        $stmt->execute();
        $users = $stmt->fetchAll();

        view('admin/users', [
            'users' => $users,
            'flash' => get_flash(),
        ]);
    }

    public function userDelete(): void
    {
        AuthMiddleware::requireAdmin();

        if (!is_post()) {
            redirect('index.php?url=admin/users');
        }

        if (!verify_csrf($_POST['csrf_token'] ?? null)) {
            set_flash('error', 'Session invalide.');
            redirect('index.php?url=admin/users');
        }

        $id = isset($_POST['id']) && ctype_digit($_POST['id']) ? (int) $_POST['id'] : 0;

        if ($id === 0 || $id === (int) current_user_id()) {
            set_flash('error', 'Action impossible.');
            redirect('index.php?url=admin/users');
        }

        $this->userModel->delete($id);
        set_flash('success', 'Utilisateur supprime.');
        redirect('index.php?url=admin/users');
    }

    public function reservations(): void
    {
        AuthMiddleware::requireAdmin();

        $reservations = $this->reservationModel->findAll();

        view('admin/reservations', [
            'reservations' => $reservations,
            'flash' => get_flash(),
        ]);
    }

    public function reservationDelete(): void
    {
        AuthMiddleware::requireAdmin();

        if (!is_post()) {
            redirect('index.php?url=admin/reservations');
        }

        if (!verify_csrf($_POST['csrf_token'] ?? null)) {
            set_flash('error', 'Session invalide.');
            redirect('index.php?url=admin/reservations');
        }

        $id = isset($_POST['id']) && ctype_digit($_POST['id']) ? (int) $_POST['id'] : 0;

        if ($id === 0) {
            redirect('index.php?url=admin/reservations');
        }

        $this->reservationModel->deleteById($id);
        set_flash('success', 'Reservation supprimee.');
        redirect('index.php?url=admin/reservations');
    }
}

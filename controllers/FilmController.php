<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class FilmController
{
    private Film $filmModel;

    public function __construct()
    {
        $this->filmModel = new Film();
    }

    public function index(): void
    {
        $genreId = isset($_GET['genre_id']) && ctype_digit($_GET['genre_id']) ? (int) $_GET['genre_id'] : null;
        $films = $this->filmModel->findAll(0, $genreId);
        $genres = $this->filmModel->allGenres();

        view('films/index', [
            'films' => $films,
            'genres' => $genres,
        ]);
    }

    public function show(): void
    {
        $id = isset($_GET['id']) && ctype_digit($_GET['id']) ? (int) $_GET['id'] : 0;

        if ($id === 0) {
            redirect('index.php?url=films');
        }

        $film = $this->filmModel->findById($id);

        if ($film === null) {
            respond_http_error(404, 'Film introuvable.');
        }

        $seances = $this->filmModel->findSeances($id);

        view('films/show', [
            'film' => $film,
            'seances' => $seances,
        ]);
    }
}

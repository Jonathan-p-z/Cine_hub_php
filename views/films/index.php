<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

$activeGenre = isset($_GET['genre_id']) && ctype_digit($_GET['genre_id']) ? (int) $_GET['genre_id'] : 0;
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>Films — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>

    <div class="catalog-header">
        <h1 class="catalog-title">Films</h1>
        <p class="catalog-subtitle">Toutes les sorties en salle.</p>
        <div class="filter-bar">
            <a href="index.php?url=films" class="filter-btn<?php echo $activeGenre === 0 ? ' filter-btn--active' : ''; ?>">Tous</a>
            <?php foreach ($genres as $genre): ?>
                <a href="index.php?url=films&genre_id=<?php echo (int) $genre['id']; ?>" class="filter-btn<?php echo $activeGenre === (int) $genre['id'] ? ' filter-btn--active' : ''; ?>"><?php echo e($genre['name']); ?></a>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="section">
        <?php if (empty($films)): ?>
            <div class="empty-state">
                <p>Aucun film disponible pour le moment.</p>
            </div>
        <?php else: ?>
            <div class="films-grid">
                <?php foreach ($films as $film): ?>
                <a href="index.php?url=films/show&id=<?php echo (int) $film['id']; ?>" class="film-card">
                    <?php if ($film['poster_url']): ?>
                        <img src="<?php echo e($film['poster_url']); ?>" alt="<?php echo e($film['title']); ?>" class="film-poster">
                    <?php else: ?>
                        <div class="film-poster-placeholder">🎬</div>
                    <?php endif; ?>
                    <div class="film-info">
                        <p class="film-title"><?php echo e($film['title']); ?></p>
                        <p class="film-meta"><?php echo e((string) $film['release_year']); ?> · <?php echo e((string) $film['duration']); ?> min</p>
                        <?php if ($film['genres']): ?>
                        <div class="film-genres">
                            <?php foreach (explode(', ', $film['genres']) as $genre): ?>
                                <span class="badge"><?php echo e(trim($genre)); ?></span>
                            <?php endforeach; ?>
                        </div>
                        <?php endif; ?>
                    </div>
                </a>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>

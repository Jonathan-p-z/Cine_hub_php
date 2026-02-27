<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>

    <?php if ($featured): ?>
    <section class="hero">
        <div class="hero-text">
            <span class="hero-eyebrow">A l'affiche</span>
            <h1 class="hero-title"><?php echo e($featured['title']); ?></h1>
            <p class="hero-synopsis"><?php echo e(mb_strimwidth($featured['synopsis'], 0, 220, '...')); ?></p>
            <div class="hero-meta">
                <span class="meta-item"><?php echo e((string) $featured['release_year']); ?></span>
                <span class="meta-item"><?php echo e((string) $featured['duration']); ?> min</span>
                <span class="meta-item"><?php echo e($featured['director']); ?></span>
            </div>
            <div class="hero-actions">
                <a href="index.php?url=films/show&id=<?php echo (int) $featured['id']; ?>" class="btn btn-primary">Voir les seances</a>
                <a href="index.php?url=films" class="btn btn-ghost">Tous les films</a>
            </div>
        </div>
        <div class="hero-poster">
            <?php if ($featured['poster_url']): ?>
                <img src="<?php echo e($featured['poster_url']); ?>" alt="<?php echo e($featured['title']); ?>">
            <?php else: ?>
                <div class="poster-placeholder">🎬</div>
            <?php endif; ?>
        </div>
    </section>
    <?php else: ?>
    <section class="hero hero--centered">
        <div class="hero-text">
            <span class="hero-eyebrow">Bienvenue</span>
            <h1 class="hero-title">Votre cinema, en ligne.</h1>
            <p class="hero-synopsis">Decouvrez les films a l'affiche, consultez les seances et reservez votre place en quelques clics.</p>
            <div class="hero-actions">
                <a href="index.php?url=films" class="btn btn-primary">Voir les films</a>
                <?php if (!is_logged_in()): ?>
                    <a href="index.php?url=auth/register" class="btn btn-ghost">Creer un compte</a>
                <?php endif; ?>
            </div>
        </div>
    </section>
    <?php endif; ?>

    <?php if (!empty($films)): ?>
    <div class="section">
        <div class="section-header">
            <h2 class="section-title">Derniers ajouts</h2>
            <a href="index.php?url=films" class="section-link">Tout voir</a>
        </div>
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
    </div>
    <?php endif; ?>
</body>
</html>

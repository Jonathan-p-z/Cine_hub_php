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
    <title><?php echo e($film['title']); ?> — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>

    <div class="film-detail">
        <div class="film-detail-poster">
            <?php if ($film['poster_url']): ?>
                <img src="<?php echo e($film['poster_url']); ?>" alt="<?php echo e($film['title']); ?>">
            <?php else: ?>
                <div class="poster-placeholder">🎬</div>
            <?php endif; ?>
        </div>

        <div class="film-detail-body">
            <h1 class="film-detail-title"><?php echo e($film['title']); ?></h1>

            <?php if ($film['genres']): ?>
            <div class="film-detail-genres">
                <?php foreach (explode(', ', $film['genres']) as $genre): ?>
                    <span class="badge"><?php echo e(trim($genre)); ?></span>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>

            <div class="film-detail-attrs">
                <div class="film-detail-attr">
                    <span class="attr-label">Annee</span>
                    <span class="attr-value"><?php echo e((string) $film['release_year']); ?></span>
                </div>
                <div class="film-detail-attr">
                    <span class="attr-label">Duree</span>
                    <span class="attr-value"><?php echo e((string) $film['duration']); ?> min</span>
                </div>
                <div class="film-detail-attr">
                    <span class="attr-label">Realisateur</span>
                    <span class="attr-value"><?php echo e($film['director']); ?></span>
                </div>
            </div>

            <p class="film-synopsis"><?php echo e($film['synopsis']); ?></p>

            <?php if (!empty($seances)): ?>
            <div class="seances-section">
                <h2 class="seances-title">Prochaines seances</h2>
                <div class="seances-list">
                    <?php foreach ($seances as $seance): ?>
                    <div class="seance-row">
                        <span class="seance-time"><?php echo e(date('d/m/Y H:i', strtotime($seance['starts_at']))); ?></span>
                        <span class="seance-room"><?php echo e($seance['salle']); ?></span>
                        <span class="seance-avail <?php echo (int) $seance['available'] === 0 ? 'seance-avail--full' : ''; ?>">
                            <?php echo (int) $seance['available']; ?> place(s)
                        </span>
                        <span class="seance-price"><?php echo number_format((float) $seance['price'], 2, ',', ''); ?> €</span>
                        <?php if ((int) $seance['available'] > 0): ?>
                            <?php if (is_logged_in()): ?>
                                <a href="index.php?url=reservations/seats&seance_id=<?php echo (int) $seance['id']; ?>" class="btn btn-primary btn-sm">Reserver</a>
                            <?php else: ?>
                                <a href="index.php?url=auth/login" class="btn btn-ghost btn-sm">Connexion requise</a>
                            <?php endif; ?>
                        <?php else: ?>
                            <span class="btn-full">Complet</span>
                        <?php endif; ?>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php else: ?>
                <p>Aucune seance disponible pour ce film.</p>
            <?php endif; ?>

            <p class="detail-back"><a href="index.php?url=films">← Retour aux films</a></p>
        </div>
    </div>
</body>
</html>

<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

$flashMessage = $flash['message'] ?? '';
$flashType = $flash['type'] ?? '';
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>Administration — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>
    <?php require BASE_PATH . '/views/partials/admin_nav.php'; ?>

    <div class="admin-page">
        <h1 class="admin-title">Tableau de bord</h1>

        <?php if ($flashMessage !== ''): ?>
            <p class="notice notice--<?php echo e($flashType); ?>"><?php echo e($flashMessage); ?></p>
        <?php endif; ?>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-value"><?php echo $stats['films']; ?></span>
                <span class="stat-label">Films</span>
                <a href="index.php?url=admin/films" class="stat-link">Gerer</a>
            </div>
            <div class="stat-card">
                <span class="stat-value"><?php echo $stats['seances']; ?></span>
                <span class="stat-label">Seances a venir</span>
                <a href="index.php?url=admin/seances" class="stat-link">Gerer</a>
            </div>
            <div class="stat-card">
                <span class="stat-value"><?php echo $stats['users']; ?></span>
                <span class="stat-label">Utilisateurs</span>
                <a href="index.php?url=admin/users" class="stat-link">Gerer</a>
            </div>
            <div class="stat-card">
                <span class="stat-value"><?php echo $stats['reservations']; ?></span>
                <span class="stat-label">Reservations</span>
                <a href="index.php?url=admin/reservations" class="stat-link">Gerer</a>
            </div>
        </div>
    </div>
</body>
</html>

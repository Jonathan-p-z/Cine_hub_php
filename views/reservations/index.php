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
    <title>Mes reservations — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>

    <div class="catalog-header">
        <h1 class="catalog-title">Mes reservations</h1>
    </div>

    <div class="section">
        <?php if ($flashMessage !== ''): ?>
            <p class="notice notice--<?php echo e($flashType); ?>"><?php echo e($flashMessage); ?></p>
        <?php endif; ?>

        <?php if (empty($reservations)): ?>
            <div class="empty-state">
                <p>Aucune reservation pour le moment.</p>
                <a href="index.php?url=films" class="btn btn-primary" style="margin-top:16px;display:inline-flex;">Voir les films</a>
            </div>
        <?php else: ?>
            <div class="resa-list">
                <?php foreach ($reservations as $r): ?>
                <div class="resa-card">
                    <div class="resa-card-header">
                        <span class="resa-film"><?php echo e($r['film_title']); ?></span>
                        <span class="resa-status <?php echo strtotime($r['starts_at']) >= time() ? 'resa-status--upcoming' : 'resa-status--past'; ?>">
                            <?php echo strtotime($r['starts_at']) >= time() ? 'A venir' : 'Passee'; ?>
                        </span>
                    </div>
                    <div class="resa-card-body">
                        <div class="resa-detail">
                            <span class="resa-detail-label">Date</span>
                            <span class="resa-detail-value"><?php echo e(date('d/m/Y H:i', strtotime($r['starts_at']))); ?></span>
                        </div>
                        <div class="resa-detail">
                            <span class="resa-detail-label">Salle</span>
                            <span class="resa-detail-value"><?php echo e($r['salle']); ?></span>
                        </div>
                        <div class="resa-detail">
                            <span class="resa-detail-label">Places</span>
                            <span class="resa-detail-value">
                                <?php echo (int) $r['seats_count']; ?> place(s) —
                                <?php foreach ($r['seats'] as $i => $seat): ?><?php echo ($i > 0 ? ', ' : '') . e($seat['seat_row'] . $seat['seat_col']); ?><?php endforeach; ?>
                            </span>
                        </div>
                        <div class="resa-detail">
                            <span class="resa-detail-label">Total</span>
                            <span class="resa-detail-value accent-text"><?php echo number_format((float) $r['price'] * (int) $r['seats_count'], 2, ',', ''); ?> €</span>
                        </div>
                    </div>
                    <?php if (strtotime($r['starts_at']) >= time()): ?>
                    <div class="resa-card-footer">
                        <form method="post" action="index.php?url=reservations/cancel" onsubmit="return confirm('Annuler cette reservation ?');">
                            <?php echo csrf_input(); ?>
                            <input type="hidden" name="id" value="<?php echo (int) $r['id']; ?>">
                            <button type="submit" class="btn-danger-sm">Annuler la reservation</button>
                        </form>
                    </div>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>

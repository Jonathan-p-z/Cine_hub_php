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
    <title>Reservations — Administration — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>
    <?php require BASE_PATH . '/views/partials/admin_nav.php'; ?>

    <div class="admin-page">
        <h1 class="admin-title">Reservations</h1>

        <?php if ($flashMessage !== ''): ?>
            <p class="notice notice--<?php echo e($flashType); ?>"><?php echo e($flashMessage); ?></p>
        <?php endif; ?>

        <?php if (empty($reservations)): ?>
            <p class="empty">Aucune reservation.</p>
        <?php else: ?>
            <div class="admin-table-wrap">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Utilisateur</th>
                            <th>Film</th>
                            <th>Seance</th>
                            <th>Salle</th>
                            <th>Places</th>
                            <th>Total</th>
                            <th>Date resa</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($reservations as $r): ?>
                        <tr>
                            <td><?php echo (int) $r['id']; ?></td>
                            <td><?php echo e($r['user_name']); ?><br><small><?php echo e($r['user_email']); ?></small></td>
                            <td><?php echo e($r['film_title']); ?></td>
                            <td><?php echo e(date('d/m/Y H:i', strtotime($r['starts_at']))); ?></td>
                            <td><?php echo e($r['salle']); ?></td>
                            <td><?php echo (int) $r['seats_count']; ?></td>
                            <td><?php echo number_format((float) $r['price'] * (float) $r['seats_count'], 2, ',', ''); ?> €</td>
                            <td><?php echo e(date('d/m/Y', strtotime($r['created_at']))); ?></td>
                            <td class="table-actions">
                                <form method="post" action="index.php?url=admin/reservations/delete" onsubmit="return confirm('Supprimer cette reservation ?');">
                                    <?php echo csrf_input(); ?>
                                    <input type="hidden" name="id" value="<?php echo (int) $r['id']; ?>">
                                    <button type="submit" class="tbl-btn tbl-btn--danger">Supprimer</button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>

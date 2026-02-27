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
    <title>Seances — Administration — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>
    <?php require BASE_PATH . '/views/partials/admin_nav.php'; ?>

    <div class="admin-page">
        <div class="admin-page-header">
            <h1 class="admin-title">Seances</h1>
            <a href="index.php?url=admin/seances/create" class="btn btn-primary">Ajouter une seance</a>
        </div>

        <?php if ($flashMessage !== ''): ?>
            <p class="notice notice--<?php echo e($flashType); ?>"><?php echo e($flashMessage); ?></p>
        <?php endif; ?>

        <?php if (empty($seances)): ?>
            <p class="empty">Aucune seance.</p>
        <?php else: ?>
            <div class="admin-table-wrap">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Film</th>
                            <th>Date &amp; heure</th>
                            <th>Salle</th>
                            <th>Places</th>
                            <th>Prix</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($seances as $seance): ?>
                        <tr>
                            <td><?php echo (int) $seance['id']; ?></td>
                            <td><?php echo e($seance['film_title']); ?></td>
                            <td><?php echo e(date('d/m/Y H:i', strtotime($seance['starts_at']))); ?></td>
                            <td><?php echo e($seance['salle']); ?></td>
                            <td><?php echo (int) $seance['reserved']; ?> / <?php echo (int) $seance['capacity']; ?></td>
                            <td><?php echo number_format((float) $seance['price'], 2, ',', ''); ?> €</td>
                            <td class="table-actions">
                                <a href="index.php?url=admin/seances/edit&id=<?php echo (int) $seance['id']; ?>" class="tbl-btn">Modifier</a>
                                <form method="post" action="index.php?url=admin/seances/delete" onsubmit="return confirm('Supprimer cette seance ?');">
                                    <?php echo csrf_input(); ?>
                                    <input type="hidden" name="id" value="<?php echo (int) $seance['id']; ?>">
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

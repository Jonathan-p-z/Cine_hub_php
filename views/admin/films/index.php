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
    <title>Films — Administration — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>
    <?php require BASE_PATH . '/views/partials/admin_nav.php'; ?>

    <div class="admin-page">
        <div class="admin-page-header">
            <h1 class="admin-title">Films</h1>
            <a href="index.php?url=admin/films/create" class="btn btn-primary">Ajouter un film</a>
        </div>

        <?php if ($flashMessage !== ''): ?>
            <p class="notice notice--<?php echo e($flashType); ?>"><?php echo e($flashMessage); ?></p>
        <?php endif; ?>

        <?php if (empty($films)): ?>
            <p class="empty">Aucun film.</p>
        <?php else: ?>
            <div class="admin-table-wrap">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Titre</th>
                            <th>Realisateur</th>
                            <th>Annee</th>
                            <th>Duree</th>
                            <th>A l'affiche</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($films as $film): ?>
                        <tr>
                            <td><?php echo (int) $film['id']; ?></td>
                            <td><?php echo e($film['title']); ?></td>
                            <td><?php echo e($film['director']); ?></td>
                            <td><?php echo (int) $film['release_year']; ?></td>
                            <td><?php echo (int) $film['duration']; ?> min</td>
                            <td><?php echo $film['featured'] ? '✓' : '—'; ?></td>
                            <td class="table-actions">
                                <a href="index.php?url=admin/films/edit&id=<?php echo (int) $film['id']; ?>" class="tbl-btn">Modifier</a>
                                <form method="post" action="index.php?url=admin/films/delete" onsubmit="return confirm('Supprimer ce film ?');">
                                    <?php echo csrf_input(); ?>
                                    <input type="hidden" name="id" value="<?php echo (int) $film['id']; ?>">
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

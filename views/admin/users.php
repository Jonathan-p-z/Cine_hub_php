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
    <title>Utilisateurs — Administration — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>
    <?php require BASE_PATH . '/views/partials/admin_nav.php'; ?>

    <div class="admin-page">
        <h1 class="admin-title">Utilisateurs</h1>

        <?php if ($flashMessage !== ''): ?>
            <p class="notice notice--<?php echo e($flashType); ?>"><?php echo e($flashMessage); ?></p>
        <?php endif; ?>

        <?php if (empty($users)): ?>
            <p class="empty">Aucun utilisateur.</p>
        <?php else: ?>
            <div class="admin-table-wrap">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Nom</th>
                            <th>Email</th>
                            <th>Roles</th>
                            <th>Inscription</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?php echo (int) $user['id']; ?></td>
                            <td><?php echo e($user['name']); ?></td>
                            <td><?php echo e($user['email']); ?></td>
                            <td><?php echo e($user['roles'] ?? '—'); ?></td>
                            <td><?php echo e(date('d/m/Y', strtotime($user['created_at']))); ?></td>
                            <td class="table-actions">
                                <?php if ((int) $user['id'] !== (int) current_user_id()): ?>
                                <form method="post" action="index.php?url=admin/users/delete" onsubmit="return confirm('Supprimer cet utilisateur ?');">
                                    <?php echo csrf_input(); ?>
                                    <input type="hidden" name="id" value="<?php echo (int) $user['id']; ?>">
                                    <button type="submit" class="tbl-btn tbl-btn--danger">Supprimer</button>
                                </form>
                                <?php else: ?>
                                    <span class="muted-text">Vous</span>
                                <?php endif; ?>
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

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
    <title>Ajouter une seance — Administration — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>
    <?php require BASE_PATH . '/views/partials/admin_nav.php'; ?>

    <div class="admin-page">
        <div class="admin-page-header">
            <h1 class="admin-title">Ajouter une seance</h1>
            <a href="index.php?url=admin/seances" class="btn btn-ghost">Retour</a>
        </div>

        <?php if (!empty($errors)): ?>
            <ul class="error-list">
                <?php foreach ($errors as $error): ?>
                    <li><?php echo e($error); ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <div class="admin-form-wrap">
            <form method="post" action="index.php?url=admin/seances/create">
                <?php echo csrf_input(); ?>

                <label for="film_id">Film</label>
                <select id="film_id" name="film_id" required>
                    <option value="">-- Choisir un film --</option>
                    <?php foreach ($films as $film): ?>
                        <option value="<?php echo (int) $film['id']; ?>" <?php echo (int) ($old['film_id'] ?? 0) === (int) $film['id'] ? 'selected' : ''; ?>>
                            <?php echo e($film['title']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>

                <label for="salle_id">Salle</label>
                <select id="salle_id" name="salle_id" required>
                    <option value="">-- Choisir une salle --</option>
                    <?php foreach ($salles as $salle): ?>
                        <option value="<?php echo (int) $salle['id']; ?>" <?php echo (int) ($old['salle_id'] ?? 0) === (int) $salle['id'] ? 'selected' : ''; ?>>
                            <?php echo e($salle['name']); ?> (<?php echo (int) $salle['capacity']; ?> places)
                        </option>
                    <?php endforeach; ?>
                </select>

                <label for="starts_at">Date et heure</label>
                <input type="datetime-local" id="starts_at" name="starts_at" required value="<?php echo e($old['starts_at'] ?? ''); ?>">

                <label for="price">Prix (€)</label>
                <input type="number" id="price" name="price" required min="0.01" step="0.01" value="<?php echo e($old['price'] ?? ''); ?>">

                <button type="submit">Ajouter la seance</button>
            </form>
        </div>
    </div>
</body>
</html>

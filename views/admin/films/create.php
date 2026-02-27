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
    <title>Ajouter un film — Administration — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>
    <?php require BASE_PATH . '/views/partials/admin_nav.php'; ?>

    <div class="admin-page">
        <div class="admin-page-header">
            <h1 class="admin-title">Ajouter un film</h1>
            <a href="index.php?url=admin/films" class="btn btn-ghost">Retour</a>
        </div>

        <?php if (!empty($errors)): ?>
            <ul class="error-list">
                <?php foreach ($errors as $error): ?>
                    <li><?php echo e($error); ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <div class="admin-form-wrap">
            <form method="post" action="index.php?url=admin/films/create">
                <?php echo csrf_input(); ?>

                <label for="title">Titre</label>
                <input type="text" id="title" name="title" required value="<?php echo e($old['title'] ?? ''); ?>">

                <label for="director">Realisateur</label>
                <input type="text" id="director" name="director" required value="<?php echo e($old['director'] ?? ''); ?>">

                <label for="synopsis">Synopsis</label>
                <textarea id="synopsis" name="synopsis" required rows="4"><?php echo e($old['synopsis'] ?? ''); ?></textarea>

                <div class="form-row">
                    <div>
                        <label for="duration">Duree (min)</label>
                        <input type="number" id="duration" name="duration" required min="1" value="<?php echo e($old['duration'] ?? ''); ?>">
                    </div>
                    <div>
                        <label for="release_year">Annee de sortie</label>
                        <input type="number" id="release_year" name="release_year" required min="1900" max="<?php echo (int) date('Y') + 5; ?>" value="<?php echo e($old['release_year'] ?? (string) date('Y')); ?>">
                    </div>
                </div>

                <label for="poster_url">URL de l'affiche (optionnel)</label>
                <input type="url" id="poster_url" name="poster_url" value="<?php echo e($old['poster_url'] ?? ''); ?>">

                <fieldset class="fieldset-genres">
                    <legend>Genres</legend>
                    <div class="genre-checkboxes">
                        <?php foreach ($genres as $genre): ?>
                            <label class="inline">
                                <input type="checkbox" name="genres[]" value="<?php echo (int) $genre['id']; ?>"
                                    <?php echo in_array((int) $genre['id'], array_map('intval', $old['genres'] ?? []), true) ? 'checked' : ''; ?>>
                                <?php echo e($genre['name']); ?>
                            </label>
                        <?php endforeach; ?>
                    </div>
                </fieldset>

                <label class="inline mt-12">
                    <input type="checkbox" name="featured" value="1" <?php echo !empty($old['featured']) ? 'checked' : ''; ?>>
                    Mettre a l'affiche (hero)
                </label>

                <button type="submit">Ajouter le film</button>
            </form>
        </div>
    </div>
</body>
</html>

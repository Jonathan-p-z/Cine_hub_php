<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

$flashMessage = $flash['message'] ?? '';
$flashType = $flash['type'] ?? '';
$deleted = isset($_GET['deleted']) && $_GET['deleted'] === '1';
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>Connexion</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <div class="page">
        <main class="panel">
            <h1>Connexion</h1>

            <?php if ($deleted): ?>
                <p class="notice">Compte supprime avec succes.</p>
            <?php endif; ?>

            <?php if ($flashMessage !== ''): ?>
                <p class="notice"><?php echo e($flashMessage); ?></p>
            <?php endif; ?>

            <?php if (!empty($errors)): ?>
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo e($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>

            <form method="post" action="index.php?url=auth/login">
                <?php echo csrf_input(); ?>
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required value="<?php echo e($email ?? ''); ?>">

                <label for="password">Mot de passe</label>
                <input type="password" id="password" name="password" required>

                <label class="inline">
                    <input type="checkbox" name="remember" value="1">
                    Se souvenir de moi
                </label>

                <button type="submit">Se connecter</button>
            </form>

            <p class="actions"><a href="index.php?url=auth/register">Creer un compte</a></p>
        </main>
    </div>
</body>
</html>

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
    <title><?php echo e($title); ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <div class="page">
        <main class="panel">
            <h1><?php echo e($title); ?></h1>
            <p><?php echo e($details); ?></p>
            <p class="actions"><a href="index.php?url=auth/login">Retour a la connexion</a></p>
        </main>
    </div>
</body>
</html>

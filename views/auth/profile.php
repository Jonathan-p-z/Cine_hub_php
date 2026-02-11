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
    <title>Profil</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <div class="page">
        <main class="panel">
            <h1>Mon profil</h1>

            <?php if ($flashMessage !== ''): ?>
                <p class="notice"><?php echo e($flashMessage); ?></p>
            <?php endif; ?>

            <p><strong>Nom:</strong> <?php echo e($user['name'] ?? ''); ?></p>
            <p><strong>Email:</strong> <?php echo e($user['email'] ?? ''); ?></p>

            <h2>Modifier le compte</h2>
            <form method="post" action="index.php?url=auth/update">
                <?php echo csrf_input(); ?>
                <label for="name">Nom</label>
                <input type="text" id="name" name="name" required value="<?php echo e($user['name'] ?? ''); ?>">

                <label for="email">Email</label>
                <input type="email" id="email" name="email" required value="<?php echo e($user['email'] ?? ''); ?>">

                <label for="password">Nouveau mot de passe (optionnel)</label>
                <input type="password" id="password" name="password" minlength="8" autocomplete="new-password">
                <div class="strength">
                    <div class="strength-bar" data-strength-bar></div>
                </div>
                <p class="strength-text" data-strength-text>Minimum 8 caracteres, majuscule, minuscule, chiffre, symbole.</p>

                <label for="confirm">Confirmer</label>
                <input type="password" id="confirm" name="confirm">

                <button type="submit">Mettre a jour</button>
            </form>

            <h2>Supprimer le compte</h2>
            <form method="post" action="index.php?url=auth/delete" onsubmit="return confirm('Confirmer la suppression du compte ?');">
                <?php echo csrf_input(); ?>
                <button type="submit">Supprimer mon compte</button>
            </form>

            <p class="actions"><a href="index.php?url=auth/logout">Se deconnecter</a></p>
        </main>
    </div>
    <script>
        (function () {
            var input = document.getElementById('password');
            var bar = document.querySelector('[data-strength-bar]');
            var text = document.querySelector('[data-strength-text]');

            if (!input || !bar || !text) {
                return;
            }

            function score(value) {
                var length = value.length;
                var variety = 0;
                if (/[A-Z]/.test(value)) variety += 1;
                if (/[a-z]/.test(value)) variety += 1;
                if (/\d/.test(value)) variety += 1;
                if (/[^A-Za-z0-9]/.test(value)) variety += 1;

                var repeats = /(.)\1\1/.test(value);
                var hasSeq = /(?:012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(value);

                if (length < 8) return 0;
                if (length < 10 || variety < 3) return 1;
                if (length < 12 || variety < 4) return 2;
                if (repeats || hasSeq) return 2;
                return 3;
            }

            function update() {
                var value = input.value || '';
                if (value.length === 0) {
                    bar.style.width = '0%';
                    bar.style.background = '#475569';
                    text.textContent = 'Minimum 8 caracteres, majuscule, minuscule, chiffre, symbole.';
                    return;
                }

                var s = score(value);
                var percent = [0, 40, 70, 100][s] || 0;
                var label = 'Faible';
                var color = '#ef4444';

                if (s === 3) {
                    label = 'Fort';
                    color = '#22c55e';
                } else if (s === 2) {
                    label = 'Moyen';
                    color = '#f59e0b';
                }

                bar.style.width = percent + '%';
                bar.style.background = color;
                text.textContent = 'Securite: ' + label + ' (min 8, maj, min, chiffre, symbole)';
            }

            input.addEventListener('input', update);
            update();
        })();
    </script>
</body>
</html>

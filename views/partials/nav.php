<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

$currentUrl = trim((string) ($_GET['url'] ?? ''), '/');
?>
<nav class="nav">
    <div class="nav-inner">
        <a href="index.php" class="nav-brand">CineHub</a>
        <div class="nav-links">
            <a href="index.php?url=films" class="nav-link<?php echo $currentUrl === 'films' ? ' nav-link--active' : ''; ?>">Films</a>
            <?php if (is_logged_in()): ?>
                <a href="index.php?url=reservations" class="nav-link<?php echo $currentUrl === 'reservations' ? ' nav-link--active' : ''; ?>">Mes reservations</a>
                <?php if (AuthMiddleware::isAdmin()): ?>
                    <a href="index.php?url=admin" class="nav-link nav-link--admin<?php echo str_starts_with($currentUrl, 'admin') ? ' nav-link--active' : ''; ?>">Admin</a>
                <?php endif; ?>
                <a href="index.php?url=auth/profile" class="nav-link<?php echo $currentUrl === 'auth/profile' ? ' nav-link--active' : ''; ?>"><?php echo e((string) ($_SESSION['user_name'] ?? '')); ?></a>
                <a href="index.php?url=auth/logout" class="nav-link">Deconnexion</a>
            <?php else: ?>
                <a href="index.php?url=auth/login" class="nav-link<?php echo $currentUrl === 'auth/login' ? ' nav-link--active' : ''; ?>">Connexion</a>
                <a href="index.php?url=auth/register" class="nav-btn">S'inscrire</a>
            <?php endif; ?>
        </div>
    </div>
</nav>

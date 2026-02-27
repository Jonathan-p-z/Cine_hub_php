<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

$adminUrl = trim((string) ($_GET['url'] ?? ''), '/');
?>
<nav class="admin-nav">
    <div class="admin-nav-inner">
        <span class="admin-nav-label">Administration</span>
        <div class="admin-nav-links">
            <a href="index.php?url=admin" class="admin-nav-link<?php echo $adminUrl === 'admin' ? ' admin-nav-link--active' : ''; ?>">Tableau de bord</a>
            <a href="index.php?url=admin/films" class="admin-nav-link<?php echo str_starts_with($adminUrl, 'admin/films') ? ' admin-nav-link--active' : ''; ?>">Films</a>
            <a href="index.php?url=admin/seances" class="admin-nav-link<?php echo str_starts_with($adminUrl, 'admin/seances') ? ' admin-nav-link--active' : ''; ?>">Seances</a>
            <a href="index.php?url=admin/users" class="admin-nav-link<?php echo $adminUrl === 'admin/users' ? ' admin-nav-link--active' : ''; ?>">Utilisateurs</a>
            <a href="index.php?url=admin/reservations" class="admin-nav-link<?php echo $adminUrl === 'admin/reservations' ? ' admin-nav-link--active' : ''; ?>">Reservations</a>
        </div>
    </div>
</nav>

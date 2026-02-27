<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

$rowLetters = range('A', chr(ord('A') + $rows - 1));
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>Choisir vos places — CineHub</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="public/css/style.css">
</head>
<body>
    <?php require BASE_PATH . '/views/partials/nav.php'; ?>

    <div class="catalog-header">
        <h1 class="catalog-title"><?php echo e($seance['film_title']); ?></h1>
        <p class="catalog-subtitle">
            <?php echo e(date('d/m/Y H:i', strtotime($seance['starts_at']))); ?> —
            <?php echo e($seance['salle']); ?> —
            <?php echo number_format((float) $seance['price'], 2, ',', ''); ?> € / place
        </p>
    </div>

    <div class="section">
        <?php if ($error !== ''): ?>
            <p class="notice notice--error"><?php echo e($error); ?></p>
        <?php endif; ?>

        <form method="post" action="index.php?url=reservations/seats&seance_id=<?php echo (int) $seance['id']; ?>" id="seat-form">
            <?php echo csrf_input(); ?>

            <div class="seat-map-wrap">
                <div class="seat-map-screen">Ecran</div>
                <div class="seat-map">
                    <?php foreach ($rowLetters as $row): ?>
                    <div class="seat-row">
                        <span class="seat-row-label"><?php echo e($row); ?></span>
                        <?php for ($col = 1; $col <= $cols; $col++): ?>
                            <?php $key = $row . $col; $taken = isset($takenKeys[$key]); ?>
                            <button type="button"
                                class="seat<?php echo $taken ? ' seat--taken' : ' seat--available'; ?>"
                                data-seat="<?php echo e($key); ?>"
                                <?php echo $taken ? 'disabled' : ''; ?>>
                                <?php echo e($key); ?>
                            </button>
                        <?php endfor; ?>
                    </div>
                    <?php endforeach; ?>
                </div>
                <div class="seat-legend">
                    <span class="seat-legend-item"><span class="seat-sample seat--available"></span> Disponible</span>
                    <span class="seat-legend-item"><span class="seat-sample seat--selected"></span> Selectionne</span>
                    <span class="seat-legend-item"><span class="seat-sample seat--taken"></span> Occupe</span>
                </div>
            </div>

            <div id="seat-inputs"></div>

            <div class="seat-summary">
                <p id="seat-count-text">Aucune place selectionnee.</p>
                <button type="submit" id="seat-submit" disabled class="btn btn-primary">Confirmer la reservation</button>
            </div>
        </form>
    </div>

    <script>
    (function () {
        var form = document.getElementById('seat-form');
        var inputsWrap = document.getElementById('seat-inputs');
        var countText = document.getElementById('seat-count-text');
        var submitBtn = document.getElementById('seat-submit');
        var selected = [];

        form.querySelectorAll('.seat--available').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var seat = btn.dataset.seat;
                var idx = selected.indexOf(seat);

                if (idx !== -1) {
                    selected.splice(idx, 1);
                    btn.classList.remove('seat--selected');
                    btn.classList.add('seat--available');
                } else {
                    selected.push(seat);
                    btn.classList.remove('seat--available');
                    btn.classList.add('seat--selected');
                }

                inputsWrap.innerHTML = '';
                selected.forEach(function (s) {
                    var inp = document.createElement('input');
                    inp.type = 'hidden';
                    inp.name = 'seats[]';
                    inp.value = s;
                    inputsWrap.appendChild(inp);
                });

                if (selected.length === 0) {
                    countText.textContent = 'Aucune place selectionnee.';
                    submitBtn.disabled = true;
                } else {
                    var total = (selected.length * <?php echo json_encode((float) $seance['price']); ?>).toFixed(2).replace('.', ',');
                    countText.textContent = selected.length + ' place(s) selectionnee(s) — Total : ' + total + ' €';
                    submitBtn.disabled = false;
                }
            });
        });
    })();
    </script>
</body>
</html>

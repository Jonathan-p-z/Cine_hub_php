<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class ReservationController
{
    private Reservation $reservationModel;
    private Seance $seanceModel;

    public function __construct()
    {
        $this->reservationModel = new Reservation();
        $this->seanceModel = new Seance();
    }

    public function index(): void
    {
        AuthMiddleware::requireAuth();

        $reservations = $this->reservationModel->findByUser((int) current_user_id());

        $withSeats = [];
        foreach ($reservations as $r) {
            $r['seats'] = $this->reservationModel->seatsByReservation((int) $r['id']);
            $withSeats[] = $r;
        }

        view('reservations/index', [
            'reservations' => $withSeats,
            'flash' => get_flash(),
        ]);
    }

    public function seats(): void
    {
        AuthMiddleware::requireAuth();

        $seanceId = isset($_GET['seance_id']) && ctype_digit($_GET['seance_id']) ? (int) $_GET['seance_id'] : 0;

        if ($seanceId === 0) {
            redirect('index.php?url=films');
        }

        $seance = $this->seanceModel->findById($seanceId);

        if ($seance === null) {
            respond_http_error(404, 'Seance introuvable.');
        }

        $taken = $this->reservationModel->seatsTaken($seanceId);
        $takenKeys = [];
        foreach ($taken as $t) {
            $takenKeys[$t['seat_row'] . $t['seat_col']] = true;
        }

        $cols = 10;
        $rows = (int) ceil($seance['capacity'] / $cols);
        $takenJson = json_encode($taken);

        if (is_post()) {
            if (!verify_csrf($_POST['csrf_token'] ?? null)) {
                set_flash('error', 'Session invalide. Merci de reessayer.');
                redirect('index.php?url=reservations/seats&seance_id=' . $seanceId);
            }

            $rawSeats = $_POST['seats'] ?? [];

            if (!is_array($rawSeats) || empty($rawSeats)) {
                view('reservations/seats', [
                    'seance' => $seance,
                    'takenKeys' => $takenKeys,
                    'takenJson' => $takenJson,
                    'cols' => $cols,
                    'rows' => $rows,
                    'error' => 'Veuillez selectionner au moins une place.',
                ]);
                return;
            }

            $seats = [];
            foreach ($rawSeats as $seat) {
                $seat = (string) $seat;
                $seats[] = ['row' => $seat[0], 'col' => (int) substr($seat, 1)];
            }

            $available = $seance['capacity'] - $this->reservationModel->countReservedSeats($seanceId);

            if (count($seats) > $available) {
                view('reservations/seats', [
                    'seance' => $seance,
                    'takenKeys' => $takenKeys,
                    'takenJson' => $takenJson,
                    'cols' => $cols,
                    'rows' => $rows,
                    'error' => 'Pas assez de places disponibles (' . $available . ' restantes).',
                ]);
                return;
            }

            $reservationId = $this->reservationModel->create((int) current_user_id(), $seanceId, $seats);

            set_flash('success', 'Reservation confirmee pour ' . count($seats) . ' place(s).');
            redirect('index.php?url=reservations');
        }

        view('reservations/seats', [
            'seance' => $seance,
            'takenKeys' => $takenKeys,
            'takenJson' => $takenJson,
            'cols' => $cols,
            'rows' => $rows,
            'error' => '',
        ]);
    }

    public function cancel(): void
    {
        AuthMiddleware::requireAuth();

        if (!is_post()) {
            redirect('index.php?url=reservations');
        }

        if (!verify_csrf($_POST['csrf_token'] ?? null)) {
            set_flash('error', 'Session invalide.');
            redirect('index.php?url=reservations');
        }

        $id = isset($_POST['id']) && ctype_digit($_POST['id']) ? (int) $_POST['id'] : 0;

        if ($id === 0) {
            redirect('index.php?url=reservations');
        }

        $reservation = $this->reservationModel->findById($id);

        if (!$reservation || (int) $reservation['user_id'] !== (int) current_user_id()) {
            set_flash('error', 'Reservation introuvable.');
            redirect('index.php?url=reservations');
        }

        $seance = $this->seanceModel->findById((int) $reservation['seance_id']);

        if ($seance && strtotime($seance['starts_at']) < time()) {
            set_flash('error', 'Impossible d\'annuler une seance passee.');
            redirect('index.php?url=reservations');
        }

        $this->reservationModel->cancel($id, (int) current_user_id());
        set_flash('success', 'Reservation annulee.');
        redirect('index.php?url=reservations');
    }
}

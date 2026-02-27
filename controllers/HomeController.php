<?php
declare(strict_types=1);

if (!defined('BASE_PATH')) {
    http_response_code(403);
    exit('Forbidden');
}

final class HomeController
{
    private Film $filmModel;

    public function __construct()
    {
        $this->filmModel = new Film();
    }

    public function index(): void
    {
        $featured = $this->filmModel->findFeatured();
        $films = $this->filmModel->findAll(8);

        view('home', [
            'featured' => $featured,
            'films' => $films,
        ]);
    }
}

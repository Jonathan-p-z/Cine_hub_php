# CineHub PHP

Application de cinema en PHP natif (sans framework) — affichage de films, reservation de places avec plan de salle interactif, et panel d'administration complet.

## Fonctionnalites

- Parcourir les films et consulter les seances disponibles
- Reserver des places avec selection interactive sur plan de salle
- Historique des reservations utilisateur avec annulation
- Inscription, connexion, modification et suppression de compte
- Panel admin : CRUD films, seances, gestion utilisateurs et reservations
- Architecture MVC stricte sans dependance externe

## Pre-requis

- PHP 8.1+, extensions PDO et pdo_mysql
- Apache avec mod_rewrite (pour .htaccess)
- MySQL ou MariaDB

## Installation

1. Importer le schema et les donnees : `sql.sql`
2. Copier `config/config.php.example` en `config/config.php` et renseigner les valeurs
3. Pointer le vhost Apache sur le dossier du projet

## Structure

```
config/         configuration, base de donnees, routes, helpers
controllers/    AuthController, HomeController, FilmController,
                ReservationController, AdminController
models/         User, Film, Seance, Reservation, SecurityLog
views/          auth/, films/, reservations/, admin/, errors/, partials/
middleware/     AuthMiddleware
public/css/     style.css
index.php       routeur frontal
sql.sql         schema complet + donnees de test
```

## Routage

Toutes les routes sont whitelistees dans `config/routes.php` et dispatchees par `index.php`.

| Route                        | Methode   | Acces       |
|------------------------------|-----------|-------------|
| home                         | GET       | public      |
| films                        | GET       | public      |
| films/show                   | GET       | public      |
| auth/login                   | GET, POST | public      |
| auth/register                | GET, POST | public      |
| auth/profile                 | GET       | authentifie |
| auth/update                  | POST      | authentifie |
| auth/delete                  | POST      | authentifie |
| auth/logout                  | POST      | authentifie |
| reservations                 | GET       | authentifie |
| reservations/seats           | GET, POST | authentifie |
| reservations/cancel          | POST      | authentifie |
| admin                        | GET       | admin       |
| admin/films                  | GET       | admin       |
| admin/films/create           | GET, POST | admin       |
| admin/films/edit             | GET, POST | admin       |
| admin/films/delete           | POST      | admin       |
| admin/seances                | GET       | admin       |
| admin/seances/create         | GET, POST | admin       |
| admin/seances/edit           | GET, POST | admin       |
| admin/seances/delete         | POST      | admin       |
| admin/users                  | GET       | admin       |
| admin/users/delete           | POST      | admin       |
| admin/reservations           | GET       | admin       |
| admin/reservations/delete    | POST      | admin       |

## Base de donnees

- `users`, `roles`, `user_roles` — gestion des utilisateurs et des roles
- `login_attempts`, `user_sessions`, `audit_logs` — securite et tracabilite
- `genres`, `films`, `film_genres` — catalogue de films
- `salles`, `seances` — salles et programmation
- `reservations`, `reservation_seats` — reservations avec contrainte d'unicite par place et seance

## Securite

- `password_hash()` / `password_verify()`
- Requetes preparees PDO uniquement, zero SQL dans les vues
- CSRF sur tous les formulaires POST
- Regeneration de session apres login, expiration par inactivite
- Empreinte de session basee sur user-agent
- Cookies HttpOnly / Secure / SameSite
- Contrainte UNIQUE sur `(seance_id, seat_row, seat_col)` pour les reservations concurrentes
- `AuthMiddleware::requireAdmin()` en entete de chaque methode admin

## Configuration

Copier `config/config.php.example` en `config/config.php` :

- `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS` — connexion MySQL
- `APP_SECRET` — cle de signature des cookies remember-me (changer en production)
- `APP_DEBUG` — affichage des erreurs (desactiver en production)
- `SESSION_LIFETIME` — duree d'inactivite en secondes
- `REMEMBER_LIFETIME` — duree du cookie "se souvenir de moi"

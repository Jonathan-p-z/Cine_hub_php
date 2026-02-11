# Cine Hub PHP - Authentification

Base technique MVC en PHP natif, centree sur l'authentification et la securite (sans framework). Cette partie ne traite que la gestion des utilisateurs et l'acces securise.

## Portee

- Architecture MVC stricte (controllers, models, views, config).
- Router frontal (index.php) avec whitelist des routes et controle des methodes HTTP.
- Connexion PDO en singleton avec mode d'erreur en exception.
- CRUD utilisateur + recherches par email / id.
- Inscription, connexion, deconnexion, modification, suppression du compte.
- Sessions securisees (regeneration ID, expiration inactivite, empreinte user-agent).
- Protection CSRF sur tous les formulaires.
- "Se souvenir de moi" avec cookie signe et rotation apres login.
- Middleware pour pages protegees.
- Protection contre acces direct aux fichiers sensibles via .htaccess.

## Pre-requis

- PHP 8.1+ avec extensions PDO et pdo_mysql
- Serveur web (Apache recommande pour .htaccess)
- MySQL ou MariaDB

## Installation

1. Creer la base de donnees et importer le script SQL :
   - Fichier : database.sql
2. Modifier la configuration :
   - config/config.php (DB_HOST, DB_NAME, DB_USER, DB_PASS, APP_SECRET)
3. Configurer le serveur web pour pointer sur le dossier du projet.
4. Ouvrir : index.php?url=auth/login

## Structure du projet

- /config : configuration, base de donnees, helpers, routes
- /controllers : AuthController
- /models : User
- /views : pages login, register, profil
- /middleware : AuthMiddleware
- /public : ressources publiques (vide par defaut)
- index.php : router frontal

## Routage

Les routes sont definies dans config/routes.php et appliquees par index.php. Exemple :

- auth/login (GET, POST)
- auth/register (GET, POST)
- auth/profile (GET)
- auth/update (POST)
- auth/delete (POST)

## Base de donnees

Script fourni dans database.sql :

- users (id, name, email, password, created_at)
- roles, user_roles (bonus)
- login_attempts (anti-bruteforce)
- user_sessions (historique des sessions)
- audit_logs (journal d'audit)

## Securite

- password_hash() / password_verify()
- Requetes preparees PDO uniquement
- Regeneration de session apres login + rotation periodique
- Expiration par inactivite
- Empreinte de session basee sur user-agent
- CSRF token sur tous les formulaires
- Mots de passe renforces + blacklist
- Anti-bruteforce par tentatives
- Journalisation securite (audit)
- Cookies HttpOnly / Secure / SameSite

## Gestion des erreurs

- Gestion centralisee des erreurs/exception
- Page HTTP commune (401/403/404/405)
- Logs applicatifs dans storage/error.log

## Configuration importante

- APP_SECRET : cle privee pour signer les cookies "remember-me".
- APP_DEBUG : affiche les erreurs en dev (false en prod).
- ERROR_LOG_FILE : chemin du log d'erreurs.
- SESSION_LIFETIME : duree d'inactivite autorisee.
- SESSION_REGEN_INTERVAL : rotation periodique de session.
- LOGIN_ATTEMPT_LIMIT / LOGIN_ATTEMPT_WINDOW : limites anti-bruteforce.
- REMEMBER_LIFETIME : duree du cookie "remember-me".

## Branches (organisation)

- auth-mvc : base MVC + authentification (structure et routes).
- securite-session : sessions durcies + CSRF + regles mdp.
- securite-logs : anti-bruteforce + logs + sessions en base.
- front-auth : UI auth + CSS.
- docs : README + documentation.
- error : page HTTP + gestion 401/403/404/405.

## URLs utiles

- index.php?url=auth/login
- index.php?url=auth/register
- index.php?url=auth/profile

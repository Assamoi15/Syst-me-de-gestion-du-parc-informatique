# Guide de déploiement — Gestion Parc Informatique (Backend Django)

Ce document explique comment configurer et déployer le backend Django de l'application de gestion de parc informatique. Il s'adresse à la personne en charge du déploiement en production.

## 1. Prérequis

- Python 3.11+ (ou version compatible avec Django 6.0)
- MySQL 8+ ou MariaDB
- pip

## 2. Installation des dépendances

```bash
pip install -r requirements.txt
```

Le projet utilise notamment `python-dotenv` pour charger la configuration depuis un fichier `.env`, ce qui évite d'avoir à modifier `settings.py` directement.

## 3. Configuration des variables d'environnement

Le projet ne contient **aucune valeur sensible en dur** dans le code. Toute la configuration (clé secrète, base de données, hôtes autorisés, CORS) passe par un fichier `.env` à la racine du projet, à côté de `manage.py`.

### Étapes

1. Copier le modèle fourni :

```bash
cp .env.example .env
```

2. Ouvrir `.env` et remplir chaque valeur. Le fichier `.env.example` contient des commentaires expliquant chaque variable et, pour certaines, la commande à exécuter en amont (ex. création de l'utilisateur MySQL).

3. **Ne jamais committer le fichier `.env`** sur Git — il est déjà exclu via `.gitignore`. Seul `.env.example` doit rester versionné.

### Détail des variables

| Variable | Description |
|---|---|
| `SECRET_KEY` | Clé secrète Django. Générer une nouvelle valeur pour la production (voir commande ci-dessous), ne jamais réutiliser celle du développement. |
| `DEBUG` | Doit être `False` en production. Sinon, toute erreur affiche le code source et les réglages internes du projet. |
| `ALLOWED_HOSTS` | Domaine(s) ou IP publique du serveur, séparés par des virgules, sans espace. |
| `DB_NAME` | Nom de la base de données MySQL. |
| `DB_USER` | Utilisateur MySQL dédié à l'application (pas `root`, voir section 4). |
| `DB_PASSWORD` | Mot de passe de cet utilisateur. |
| `DB_HOST` | Adresse du serveur MySQL (`127.0.0.1` si sur la même machine). |
| `DB_PORT` | Port MySQL (`3306` par défaut). |
| `CORS_ALLOWED_ORIGINS` | Domaine(s) du front autorisé(s) à appeler cette API, séparés par des virgules. |
| `QR_SCAN_BASE_URL` | Adresse publique en HTTPS permettant à un téléphone d'ouvrir une fiche après scan d'un QR code. |

Générer une nouvelle `SECRET_KEY` :

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

## 4. Base de données

### Créer la base (si elle n'existe pas déjà)

```sql
CREATE DATABASE gestion_parc_informatique CHARACTER SET utf8mb4;
```

### Créer un utilisateur MySQL dédié

Ne pas utiliser le compte `root` en production. Créer un utilisateur qui n'a de droits que sur cette base :

```sql
CREATE USER 'parc_app'@'localhost' IDENTIFIED BY 'mot_de_passe_fort_a_definir';
GRANT ALL PRIVILEGES ON gestion_parc_informatique.* TO 'parc_app'@'localhost';
FLUSH PRIVILEGES;
```

Reporter ces identifiants dans `.env` (`DB_USER`, `DB_PASSWORD`).

Si le serveur MySQL n'est pas sur la même machine que l'application, remplacer `'localhost'` par l'IP du serveur applicatif ou par `'%'` dans le `CREATE USER`.

### Appliquer les migrations

```bash
python manage.py migrate
```

## 5. Fichiers statiques

```bash
python manage.py collectstatic
```

Cela regroupe les fichiers statiques dans le dossier défini par `STATIC_ROOT`, à servir ensuite via le serveur web (nginx, Apache, etc.), et non par Django lui-même.

## 6. HTTPS

L'application utilise l'authentification JWT (identifiants, tokens transmis à chaque requête). En HTTP simple, ces informations circulent en clair.

- Configurer un certificat HTTPS sur le serveur web placé devant Django (nginx, Apache, ou un reverse proxy).
- Rediriger tout le trafic HTTP vers HTTPS.
- Une fois HTTPS actif, s'assurer que les réglages suivants sont bien activés dans `settings.py` (déjà en place, à vérifier) :

```python
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
```

## 7. Serveur d'application

Ne pas utiliser `python manage.py runserver` en production — cette commande n'est pas conçue pour ça. Utiliser un serveur WSGI dédié, par exemple Gunicorn :

```bash
pip install gunicorn
gunicorn config.wsgi:application --bind 0.0.0.0:8000
```

À placer ensuite derrière un serveur web (nginx) qui gère le HTTPS et sert les fichiers statiques.

## 8. Vérification finale

Une fois `.env` rempli avec les valeurs de production, lancer la commande d'audit automatique de Django :

```bash
python manage.py check --deploy
```

Cette commande signale les réglages de sécurité manquants ou incorrects avant la mise en ligne.

## 9. Checklist récapitulative

- [ ] `.env` créé et rempli avec les valeurs de production
- [ ] `DEBUG=False`
- [ ] `SECRET_KEY` régénérée, différente de celle du développement
- [ ] `ALLOWED_HOSTS` renseigné avec le vrai domaine/IP
- [ ] Utilisateur MySQL dédié créé (pas `root`)
- [ ] Migrations appliquées (`migrate`)
- [ ] Fichiers statiques collectés (`collectstatic`)
- [ ] HTTPS configuré sur le serveur web
- [ ] `CORS_ALLOWED_ORIGINS` limité au(x) domaine(s) du front
- [ ] `QR_SCAN_BASE_URL` mis à jour avec l'adresse publique HTTPS
- [ ] `python manage.py check --deploy` exécuté sans erreur critique
- [ ] Sauvegardes de la base de données mises en place

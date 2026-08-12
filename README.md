# Système de Gestion du Parc Informatique

Ce projet consiste en une application web backend robuste conçue pour la gestion, le suivi et la maintenance du parc informatique d'un cabinet. Elle permet de suivre l'état des équipements, d'assigner le matériel aux collaborateurs et de centraliser les demandes d'assistance ou de maintenance.

## 🚀 Fonctionnalités Clés
- **Authentification Sécurisée** : Gestion de l'accès par rôles (Utilisateurs, Techniciens, Administrateurs) basée sur des jetons JWT.
- **Gestion des Équipements** : Suivi complet du cycle de vie du matériel (ordinateurs, serveurs, périphériques).
- **Attribution & Affectation** : Traçabilité précise de quel équipement est affecté à quel collaborateur ou service.
- **Maintenance & Tickets** : Système de signalement des pannes et de suivi de la résolution des incidents technologiques.

## 🛠️ Technologies Utilisées
- **Langage** : Python 3.12+
- **Framework Principal** : [Django](https://djangoproject.com)
- **Architecture API** : [Django REST Framework (DRF)](https://django-rest-framework.org)
- **Sécurité** : [PyJWT](https://readthedocs.io) (Authentification par Token JWT) & Django Rest Framework Authtoken

## 📦 Installation et Configuration en Local

### Prerequisites
- Python 3.12 ou version supérieure installé.
- Git installé.

### 1. Cloner le dépôt
```bash
git clone https://github.com
cd Syst-me-de-gestion-du-parc-informatique
```

### 2. Activer l'environnement virtuel
Sous Windows (Git Bash) :
```bash
source env/Scripts/activate
```

### 3. Installer les dépendances
*(Assurez-vous de générer votre fichier requirements.txt si ce n'est pas déjà fait)*
```bash
pip install -r requirements.txt
```

### 4. Appliquer les migrations de base de données
```bash
python manage.py migrate
```

### 5. Lancer le serveur de développement
```bash
python manage.py runserver
```
L'API sera accessible localement à l'adresse : `http://127.0.0`

## Guide de reprise pour les développeurs

### Démarrage sur le réseau local

Pour tester le front ou le scan depuis un téléphone connecté au même Wi-Fi,
démarrer Django sur toutes les interfaces :

```powershell
.\env\Scripts\python.exe manage.py runserver 0.0.0.0:8000
```

L'adresse de développement configurée est `http://192.168.1.5:8000`.
Si l'adresse IP du PC change, mettre à jour `ALLOWED_HOSTS` et
`QR_SCAN_BASE_URL` dans `config/settings.py`, puis réimprimer les étiquettes.

### Conventions API

- Toutes les routes API commencent par `/api/` et se terminent par `/`.
- Les routes de gestion nécessitent `Authorization: Bearer <access_token>`.
- Le token est obtenu via `POST /api/login/` et contient `matricule` et `role`.
- La route publique de scan est `GET /api/equipements/scan/?qr_code=...`.
- Les erreurs suivent la forme `{ "error": "message" }`.

### Cycle QR code

1. `POST /api/parc/equipements/` crée l'équipement et sa valeur `qr_code`.
2. `GET /api/parc/equipements/{id}/etiquette/` produit une page HTML à imprimer.
3. L'étiquette encode l'URL de scan configurée dans `QR_SCAN_BASE_URL`.
4. Le téléphone appelle `GET /api/equipements/scan/?qr_code=...` sans JWT.

### Endpoints utiles au front

| Usage | Endpoint |
|---|---|
| Connexion | `POST /api/login/` |
| Équipements | `GET, POST /api/parc/equipements/` |
| Export équipements Excel | `GET /api/parc/equipements/?format=excel` |
| Étiquette QR | `GET /api/parc/equipements/{id}/etiquette/` |
| Scan et fiche équipement | `GET /api/equipements/scan/?qr_code=...` |
| Historique Excel | `GET /api/parc/historique-global/?format=excel` |
| Demandes agent | `POST /api/agent/demandes/`, `GET /api/agent/demandes/suivi/` |
| Pannes | `POST /api/agent/pannes/signaler/` |

### Points d'architecture

- `parc/views.py` contient la logique HTTP et les requêtes SQL sur la base MySQL.
- `config/urls.py` est la liste unique des routes publiques.
- `parc/authentication.py` transforme les claims JWT en utilisateur DRF léger.
- `openpyxl` génère les exports `.xlsx`; `qrcode` génère les images des étiquettes.
- Les commentaires et docstrings décrivent les règles non évidentes. Éviter de
  dupliquer en commentaire ce que le code exprime déjà clairement.

### Avant la production

- Remplacer l'IP locale dans `QR_SCAN_BASE_URL` par le domaine public.
- Passer `DEBUG` à `False` et protéger `SECRET_KEY` et les identifiants MySQL.
- Restreindre `CORS_ALLOW_ALL_ORIGINS` aux domaines autorisés.
- Remplacer le hasher MD5 utilisé pour les tests par un hasher sécurisé.

## 👥 Contributeurs
- **Assamoi** ([@Assamoi15](https://github.com))

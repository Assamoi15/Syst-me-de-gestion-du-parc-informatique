# Syst-me-de-gestion-du-parc-informatique
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

## 👥 Contributeurs
- **Assamoi** ([@Assamoi15](https://github.com))


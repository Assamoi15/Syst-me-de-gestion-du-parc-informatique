#!/bin/bash
# Script de déploiement Parc Informatique Backend
# Usage: sudo bash deploy/deploy.sh

set -e

PROJECT_DIR="/var/www/parc/backend"
VENV_DIR="$PROJECT_DIR/venv"
LOG_DIR="/var/log/parc"
RUN_DIR="/var/run/parc"

echo "=== Déploiement Parc Informatique Backend ==="

echo "Création des répertoires..."
mkdir -p "$LOG_DIR" "$RUN_DIR"
chown -R www-data:www-data "$LOG_DIR" "$RUN_DIR"

cd "$PROJECT_DIR"

if [ ! -d "$VENV_DIR" ]; then
    echo "Création de l'environnement virtuel..."
    python3.11 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

echo "Installation des dépendances..."
pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f "$PROJECT_DIR/.env" ]; then
    echo "ERREUR: fichier .env manquant. Copier deploy/.env.production.example vers .env et le remplir." >&2
    exit 1
fi

echo "Collecte des fichiers statiques..."
python manage.py collectstatic --noinput

echo "Application des migrations..."
python manage.py migrate --noinput

echo "Vérification de sécurité Django..."
python manage.py check --deploy || true

echo "Configuration des services systemd..."
cp deploy/parc-gunicorn.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable parc-gunicorn
systemctl restart parc-gunicorn

echo "Configuration Nginx..."
cp deploy/nginx-parc.conf /etc/nginx/sites-available/parc
ln -sf /etc/nginx/sites-available/parc /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

echo "=== Déploiement terminé ==="
systemctl status parc-gunicorn --no-pager

echo ""
echo "Commandes utiles:"
echo "  - Logs Gunicorn: journalctl -u parc-gunicorn -f"
echo "  - Redémarrer: sudo systemctl restart parc-gunicorn"

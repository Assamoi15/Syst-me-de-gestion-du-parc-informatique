"""Crée des comptes fictifs (un par rôle) et quelques équipements de démonstration.

Usage : ``python manage.py seed_demo``. Idempotent : les comptes existants voient
leur mot de passe, rôle et statut réinitialisés; les équipements déjà présents
(même code_inventaire) ne sont pas dupliqués.
"""

from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand
from django.db import connection, transaction

UTILISATEURS = [
    # matricule, nom, prenom, telephone, role, mot_de_passe
    ("ADM-2026-001", "Kone", "Awa", "0700000001", "ADMINISTRATEUR", "Admin@2026"),
    ("RP-2026-001", "Yao", "Jean", "0700000002", "RESPONSABLE_PARC", "Parc@2026"),
    ("DIR-2026-001", "Traore", "Mariam", "0700000003", "DIRECTEUR", "Directeur@2026"),
    ("AG-2026-001", "Kouame", "Serge", "0700000004", "AGENT_BENEFICIAIRE", "Agent@2026"),
    ("AG-2026-002", "Bamba", "Fatou", "0700000005", "AGENT_BENEFICIAIRE", "Agent@2026"),
]

EQUIPEMENTS = [
    # code_inventaire, designation, marque, modele, etat, description
    ("PC-0001", "Ordinateur portable", "Dell", "Latitude 5440", "DISPONIBLE", "i5, 16 Go RAM"),
    ("PC-0002", "Ordinateur portable", "HP", "EliteBook 840", "DISPONIBLE", "i7, 16 Go RAM"),
    ("PC-0003", "Ordinateur portable", "Lenovo", "ThinkPad T14", "AFFECTE", "Affecté à AG-2026-001"),
    ("IMP-0001", "Imprimante", "Canon", "i-SENSYS MF445", "DISPONIBLE", "Laser multifonction"),
    ("ECR-0001", "Ecran", "Samsung", "S24", "DISPONIBLE", "24 pouces"),
]


class Command(BaseCommand):
    help = "Crée des utilisateurs fictifs pour chaque rôle et des équipements de démo."

    @transaction.atomic
    def handle(self, *args, **options):
        with connection.cursor() as cursor:
            for matricule, nom, prenom, tel, role, mdp in UTILISATEURS:
                cursor.execute(
                    "INSERT INTO UTILISATEUR (matricule, nom, prenom, mot_de_passe, telephone, date_creation, role, is_active) "
                    "VALUES (%s, %s, %s, %s, %s, CURDATE(), %s, 1) "
                    "ON DUPLICATE KEY UPDATE nom=VALUES(nom), prenom=VALUES(prenom), mot_de_passe=VALUES(mot_de_passe), "
                    "telephone=VALUES(telephone), role=VALUES(role), is_active=1",
                    [matricule, nom, prenom, make_password(mdp), tel, role],
                )
                self.stdout.write(f"  {role:<20} {matricule:<14} {mdp}")

            for code, designation, marque, modele, etat, desc in EQUIPEMENTS:
                cursor.execute("SELECT 1 FROM EQUIPEMENT WHERE code_inventaire = %s", [code])
                if cursor.fetchone():
                    continue
                cursor.execute(
                    "INSERT INTO EQUIPEMENT (code_inventaire, designation, marque, modele, date_acquisition, etat, description, qr_code) "
                    "VALUES (%s, %s, %s, %s, CURDATE(), %s, %s, %s)",
                    [code, designation, marque, modele, etat, desc, f"QR_{code}"],
                )
                if etat == "AFFECTE":
                    cursor.execute(
                        "INSERT INTO AFFECTATION (date_affectation, date_restitution, statut, matricule_agent, id_equipement, matricule_responsable) "
                        "VALUES (CURDATE(), NULL, 'EN_COURS', 'AG-2026-001', %s, 'RP-2026-001')",
                        [cursor.lastrowid],
                    )

        self.stdout.write(self.style.SUCCESS("Données de démonstration prêtes."))

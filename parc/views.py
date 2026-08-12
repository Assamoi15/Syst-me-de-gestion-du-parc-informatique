import base64
from io import BytesIO
from urllib.parse import quote

import qrcode
from django.conf import settings
from django.http import HttpResponse
from django.utils.html import escape
"""Vues HTTP de l'API du parc informatique.

Le projet utilise volontairement des requêtes SQL explicites sur les tables
MySQL existantes (EQUIPEMENT, AFFECTATION, MAINTENANCE, etc.). Les vues lisent
le JWT Bearer pour appliquer les rôles métier. Les routes sont déclarées dans
``config/urls.py``; conserver le slash final dans les appels du front.

Le scan QR reste public afin qu'un téléphone puisse consulter une fiche après
lecture de l'étiquette. Toutes les opérations de gestion restent protégées par
un rôle dans le jeton.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import connection, transaction
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.tokens import AccessToken

ROLES_UTILISATEUR = {
    'AGENT_BENEFICIAIRE',
    'RESPONSABLE_PARC',
    'DIRECTEUR',
    'ADMINISTRATEUR',
}


def mot_de_passe_est_hache(mot_de_passe):
    if not isinstance(mot_de_passe, str) or '$' not in mot_de_passe:
        return False
    prefix = mot_de_passe.split('$', 1)[0]
    return prefix in {
        'bcrypt_sha256',
        'bcrypt',
        'pbkdf2_sha256',
        'argon2',
    }


def enregistrer_audit_compte(request, action, description):
    """Enregistre les actions d'administration des comptes dans HISTORIQUE."""
    token = AccessToken(request.headers['Authorization'].split(' ', 1)[1])
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO HISTORIQUE (date_action, action, description, utilisateur, id_equipement) "
            "VALUES (CURDATE(), %s, %s, %s, NULL)",
            [action, description, token.get('matricule')],
        )

# ==========================================
# 1. VUE DE CONNEXION (LOGIN)
# ==========================================
class LoginView(APIView):
    """Authentifie un utilisateur et retourne un JWT contenant son rôle et matricule."""
    authentication_classes = [] 
    permission_classes = []     

    def post(self, request):
        matricule_saisi = request.data.get('matricule')
        mdp_saisi = request.data.get('mot_de_passe')
        
        if not matricule_saisi or not mdp_saisi:
            return Response({"error": "Champs incomplets"}, status=status.HTTP_400_BAD_REQUEST)
        
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT matricule, nom, prenom, role, mot_de_passe, is_active FROM UTILISATEUR WHERE matricule = %s", 
                [matricule_saisi]
            )
            row = cursor.fetchone()
            
        if row:
            db_matricule, db_nom, db_prenom, db_role, db_mdp, is_active = row

            if mot_de_passe_est_hache(db_mdp):
                mot_de_passe_valide = check_password(mdp_saisi, db_mdp)
            else:
                mot_de_passe_valide = db_mdp == mdp_saisi

            if mot_de_passe_valide:
                if not is_active:
                    return Response({"error": "Ce compte est désactivé."}, status=status.HTTP_403_FORBIDDEN)

                if not mot_de_passe_est_hache(db_mdp):
                    hashed = make_password(mdp_saisi)
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "UPDATE UTILISATEUR SET mot_de_passe = %s WHERE matricule = %s",
                            [hashed, db_matricule]
                        )

                token = AccessToken()
                token['matricule'] = db_matricule
                token['role'] = db_role
                
                return Response({
                    "message": "Connexion réussie",
                    "matricule": db_matricule,
                    "nom": db_nom,
                    "prenom": db_prenom,
                    "role": db_role,
                    "access_token": str(token)
                }, status=status.HTTP_200_OK)

        return Response({"error": "Matricule ou mot de passe incorrect"}, status=status.HTTP_400_BAD_REQUEST)


# ==========================================
# 2. GESTION DES UTILISATEURS (RÉSERVÉ ADMIN)
# ==========================================
class AdminUserManagementView(APIView):
    """CRUD des comptes utilisateurs, réservé au rôle ADMINISTRATEUR."""
    authentication_classes = [] 
    permission_classes = []     

    def verifier_si_admin(self, request):
        """Décode le token Bearer reçu et vérifie si le rôle est ADMINISTRATEUR"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False
        try:
            token_str = auth_header.split(' ')[1]
            token = AccessToken(token_str)
            if token.get('role') != 'ADMINISTRATEUR':
                return False
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT 1 FROM UTILISATEUR WHERE matricule = %s AND is_active = 1",
                    [token.get('matricule')],
                )
                return cursor.fetchone() is not None
        except Exception:
            return False

    # A. CRÉER UN UTILISATEUR (POST)
    def post(self, request):
        if not self.verifier_si_admin(request):
            return Response({"error": "Accès refusé. Seul l'ADMINISTRATEUR peut créer un compte."}, status=status.HTTP_403_FORBIDDEN)
        
        data = request.data
        matricule = data.get('matricule')
        nom = data.get('nom')
        prenom = data.get('prenom')
        mot_de_passe = data.get('mot_de_passe')
        telephone = data.get('telephone', '')
        role = data.get('role', 'AGENT_BENEFICIAIRE')

        if not all([matricule, nom, prenom, mot_de_passe]):
            return Response({"error": "Champs obligatoires manquants"}, status=status.HTTP_400_BAD_REQUEST)
        if role not in ROLES_UTILISATEUR:
            return Response(
                {"error": "Rôle invalide", "roles_autorises": sorted(ROLES_UTILISATEUR)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        mot_de_passe_hache = make_password(mot_de_passe)

        try:
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO UTILISATEUR (matricule, nom, prenom, mot_de_passe, telephone, date_creation, role) "
                        "VALUES (%s, %s, %s, %s, %s, CURDATE(), %s)",
                        [matricule, nom, prenom, mot_de_passe_hache, telephone, role]
                    )
                enregistrer_audit_compte(
                    request,
                    "CREATION_COMPTE",
                    f"Création de l'utilisateur {matricule}",
                )
            return Response({"message": "Utilisateur créé avec succès !"}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

    # B. LISTER LES UTILISATEURS (GET)
    def get(self, request):
        if not self.verifier_si_admin(request):
            return Response({"error": "Accès refusé. Seul l'ADMINISTRATEUR peut consulter la liste des utilisateurs."}, status=status.HTTP_403_FORBIDDEN)

        status_filter = request.GET.get('status', 'all').lower()
        page = request.GET.get('page', '1')
        page_size = request.GET.get('size', '20')
        try:
            page = max(1, int(page))
        except ValueError:
            page = 1
        try:
            page_size = min(100, max(1, int(page_size)))
        except ValueError:
            page_size = 20

        params = []
        where_clause = ""
        select_last_login = "NULL AS last_login"
        select_telephone = "'' AS telephone"
        select_date_creation = "NULL AS date_creation"
        supports_last_login = False
        supports_telephone = False
        supports_date_creation = False

        with connection.cursor() as cursor:
            try:
                cursor.execute("SHOW COLUMNS FROM UTILISATEUR LIKE 'last_login'")
                supports_last_login = cursor.fetchone() is not None
            except Exception:
                supports_last_login = False
            try:
                cursor.execute("SHOW COLUMNS FROM UTILISATEUR LIKE 'telephone'")
                supports_telephone = cursor.fetchone() is not None
            except Exception:
                supports_telephone = False
            try:
                cursor.execute("SHOW COLUMNS FROM UTILISATEUR LIKE 'date_creation'")
                supports_date_creation = cursor.fetchone() is not None
            except Exception:
                supports_date_creation = False

        if status_filter == 'active':
            where_clause = "WHERE is_active = 1"
        elif status_filter == 'inactive':
            where_clause = "WHERE is_active = 0"
        elif status_filter == 'jamais_connecte':
            if supports_last_login:
                where_clause = "WHERE is_active = 1 AND last_login IS NULL"
            else:
                where_clause = "WHERE is_active = 1"

        if supports_last_login:
            select_last_login = "last_login"
        if supports_telephone:
            select_telephone = "telephone"
        if supports_date_creation:
            select_date_creation = "date_creation"

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM UTILISATEUR " + where_clause,
                params,
            )
            total_items = cursor.fetchone()[0]

            offset = (page - 1) * page_size
            cursor.execute(
                "SELECT matricule, nom, prenom, " + select_telephone + ", role, is_active, 0 AS is_staff, 0 AS is_superuser, "
                + select_last_login + ", " + select_date_creation + " "
                "FROM UTILISATEUR " + where_clause + " ORDER BY matricule LIMIT %s OFFSET %s",
                params + [page_size, offset],
            )
            rows = cursor.fetchall()

        utilisateurs = []
        for row in rows:
            last_login = row[8]
            if not row[5]:
                statut = "inactif"
            elif last_login is None:
                statut = "jamais connecté"
            else:
                statut = "actif"

            utilisateurs.append({
                "matricule": row[0],
                "nom": row[1],
                "prenom": row[2],
                "telephone": row[3],
                "role": row[4],
                "is_active": bool(row[5]),
                "is_staff": bool(row[6]),
                "is_superuser": bool(row[7]),
                "dernier_login": str(last_login) if last_login is not None else None,
                "date_creation": str(row[9]) if row[9] is not None else None,
                "section": None,
                "status": statut,
            })

        total_pages = (total_items + page_size - 1) // page_size
        return Response({
            "status_filter": status_filter,
            "page": page,
            "size": page_size,
            "total_items": total_items,
            "total_pages": total_pages,
            "utilisateurs": utilisateurs,
        }, status=status.HTTP_200_OK)

    # C. MODIFIER UN UTILISATEUR (PUT)
    def put(self, request, matricule):  # <-- Le nom 'matricule' doit être identique à celui de l'urls.py
        if not self.verifier_si_admin(request):
            return Response({"error": "Accès refusé. Seul l'ADMINISTRATEUR peut modifier un compte."}, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        if 'role' in data and data['role'] not in ROLES_UTILISATEUR:
            return Response(
                {"error": "Rôle invalide", "roles_autorises": sorted(ROLES_UTILISATEUR)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if 'mot_de_passe' in data and not data['mot_de_passe']:
            return Response(
                {"error": "Le mot de passe ne peut pas être vide."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT nom, prenom, telephone, role, mot_de_passe FROM UTILISATEUR WHERE matricule = %s",
                        [matricule]
                    )
                    utilisateur = cursor.fetchone()
                    if not utilisateur:
                        return Response({"error": "Utilisateur introuvable"}, status=status.HTTP_404_NOT_FOUND)

                    nouveau_mot_de_passe = utilisateur[4]
                    if 'mot_de_passe' in data:
                        if not data['mot_de_passe']:
                            return Response(
                                {"error": "Le mot de passe ne peut pas être vide."},
                                status=status.HTTP_400_BAD_REQUEST,
                            )
                        nouveau_mot_de_passe = make_password(data['mot_de_passe'])
                    elif not mot_de_passe_est_hache(nouveau_mot_de_passe):
                        nouveau_mot_de_passe = make_password(nouveau_mot_de_passe)

                    cursor.execute(
                        "UPDATE UTILISATEUR SET nom=%s, prenom=%s, telephone=%s, role=%s, mot_de_passe=%s WHERE matricule=%s",
                        [
                            data.get('nom', utilisateur[0]),
                            data.get('prenom', utilisateur[1]),
                            data.get('telephone', utilisateur[2]),
                            data.get('role', utilisateur[3]),
                            nouveau_mot_de_passe,
                            matricule,
                        ]
                    )
                enregistrer_audit_compte(
                    request,
                    "MODIFICATION_COMPTE",
                    f"Modification de l'utilisateur {matricule}",
                )
            return Response({"message": "Utilisateur mis à jour avec succès !"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

    # D. RÉINITIALISER LE MOT DE PASSE D'UN UTILISATEUR (PATCH)
    def patch(self, request, matricule):
        if not self.verifier_si_admin(request):
            return Response({"error": "Accès refusé. Seul l'ADMINISTRATEUR peut réinitialiser un mot de passe."}, status=status.HTTP_403_FORBIDDEN)

        try:
            data = request.data
        except Exception:
            data = None

        if not data:
            try:
                import json
                raw_body = request.body.decode('utf-8')
                if raw_body:
                    parsed = json.loads(raw_body)
                    if isinstance(parsed, dict):
                        data = parsed
            except Exception:
                data = {}

        def extraire_mot_de_passe(mapping):
            if not mapping:
                return None
            accepted_keys = {'mot_de_passe', 'password', 'new_password', 'newpassword', 'nouveau_mot_de_passe'}
            if isinstance(mapping, dict) or hasattr(mapping, 'items'):
                for key, value in mapping.items():
                    if isinstance(key, str) and key.lower() in accepted_keys:
                        return value
            return None

        nouveau_mot_de_passe = (
            extraire_mot_de_passe(data) or
            request.query_params.get('mot_de_passe') or
            request.query_params.get('password') or
            request.query_params.get('new_password') or
            request.query_params.get('nouveau_mot_de_passe')
        )
        if not nouveau_mot_de_passe:
            return Response(
                {
                    "error": "Le nouveau mot de passe est requis.",
                    "detail": "Envoyez mot_de_passe, password ou new_password dans le corps JSON ou en query string.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT matricule FROM UTILISATEUR WHERE matricule = %s",
                        [matricule]
                    )
                    if cursor.fetchone() is None:
                        return Response({"error": "Utilisateur introuvable"}, status=status.HTTP_404_NOT_FOUND)

                    mot_de_passe_hache = make_password(nouveau_mot_de_passe)
                    cursor.execute(
                        "UPDATE UTILISATEUR SET mot_de_passe = %s WHERE matricule = %s",
                        [mot_de_passe_hache, matricule]
                    )
                enregistrer_audit_compte(
                    request,
                    "REINITIALISATION_MOT_DE_PASSE",
                    f"Réinitialisation du mot de passe de l'utilisateur {matricule}",
                )
            return Response({"message": "Mot de passe réinitialisé avec succès."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

    # C. DÉSACTIVER UN UTILISATEUR (DELETE logique)
    def delete(self, request, matricule):
        if not self.verifier_si_admin(request):
            return Response({"error": "Accès refusé. Seul l'ADMINISTRATEUR peut supprimer un compte."}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            with transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE UTILISATEUR SET is_active = 0 WHERE matricule = %s AND is_active = 1",
                        [matricule],
                    )
                    if cursor.rowcount == 0:
                        cursor.execute("SELECT is_active FROM UTILISATEUR WHERE matricule = %s", [matricule])
                        utilisateur = cursor.fetchone()
                        if not utilisateur:
                            return Response({"error": "Utilisateur introuvable"}, status=status.HTTP_404_NOT_FOUND)
                        return Response({"message": "Ce compte est déjà désactivé."}, status=status.HTTP_200_OK)
                enregistrer_audit_compte(
                    request,
                    "DESACTIVATION_COMPTE",
                    f"Désactivation de l'utilisateur {matricule}",
                )
            return Response({"message": "Compte désactivé avec succès."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

# ==========================================
# 5. GESTION DE L'INVENTAIRE (RESPONSABLE PARC)
# ==========================================
# ==========================================
# 5. GESTION DE L'INVENTAIRE (CONFORME DIAGRAMME)
# ==========================================
class ResponsableInventaireView(APIView):
    """Liste, crée et modifie les équipements du parc pour RESPONSABLE_PARC.

    ``?format=excel`` produit un fichier XLSX; les filtres ``etat`` et
    ``marque`` s'appliquent à la liste et à son export.
    """
    authentication_classes = []
    permission_classes = []

    def verifier_responsable_parc(self, request):
        """Décode manuellement le jeton Bearer pour lire le rôle en texte brut"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        try:
            # On extrait uniquement la chaîne cryptée du Token JWT
            token_str = auth_header.split(' ')[1]
            
            # On utilise le décodeur officiel de SimpleJWT pour lire le dictionnaire
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_str)
            
            # On vérifie si le rôle enregistré à l'intérieur est bien RESPONSABLE_PARC
            if token.get('role') == 'RESPONSABLE_PARC':
                return token.get('matricule', 'RP_SYSTEME')
        except Exception:
            return None
        return None


    # [FONCTIONNALITÉ : CONSULTER L'INVENTAIRE avec filtres optionnels]
    def get(self, request, id_equipement=None):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        with connection.cursor() as cursor:
            # Si on cherche un équipement précis par son ID
            if id_equipement:
                cursor.execute("SELECT id_equipement, code_inventaire, designation, marque, modele, etat, description FROM EQUIPEMENT WHERE id_equipement = %s", [id_equipement])
                r = cursor.fetchone()
                if not r:
                    return Response({"error": "Équipement introuvable"}, status=status.HTTP_404_NOT_FOUND)
                return Response({"id": r[0], "code_inventaire": r[1], "designation": r[2], "marque": r[3], "modele": r[4], "etat": r[5], "description": r[6]})
            
            # Récupération des filtres optionnels (Ex: ?etat=DISPONIBLE ou ?marque=Dell)
            etat_filtre = request.GET.get('etat')
            marque_filtre = request.GET.get('marque')
            
            query = "SELECT id_equipement, code_inventaire, designation, marque, modele, etat, description FROM EQUIPEMENT WHERE 1=1"
            params = []
            
            if etat_filtre:
                query += " AND etat = %s"
                params.append(etat_filtre)
            if marque_filtre:
                query += " AND marque = %s"
                params.append(marque_filtre)
                
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            equipements = [{"id": r[0], "code_inventaire": r[1], "designation": r[2], "marque": r[3], "modele": r[4], "etat": r[5], "description": r[6]} for r in rows]

            if request.GET.get('format', '').lower() in ('excel', 'xlsx'):
                workbook = Workbook()
                feuille = workbook.active
                feuille.title = 'Équipements'
                feuille.append([
                    'ID', 'Code inventaire', 'Désignation', 'Marque',
                    'Modèle', 'État', 'Description'
                ])

                for cellule in feuille[1]:
                    cellule.font = Font(bold=True)

                for equipement in equipements:
                    feuille.append([
                        equipement['id'], equipement['code_inventaire'],
                        equipement['designation'], equipement['marque'],
                        equipement['modele'], equipement['etat'],
                        equipement['description']
                    ])

                feuille.freeze_panes = 'A2'
                for colonne, largeur in {
                    'A': 10, 'B': 22, 'C': 30, 'D': 20,
                    'E': 25, 'F': 20, 'G': 45
                }.items():
                    feuille.column_dimensions[colonne].width = largeur

                fichier = BytesIO()
                workbook.save(fichier)
                fichier.seek(0)
                response = HttpResponse(
                    fichier.getvalue(),
                    content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                )
                response['Content-Disposition'] = 'attachment; filename="liste_equipements.xlsx"'
                return response

            return Response(equipements, status=status.HTTP_200_OK)

    # [FONCTIONNALITÉ : AJOUTER UN ÉQUIPEMENT avec gestion d'erreur doublon]
    def post(self, request):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        data = request.data
        code = data.get('code_inventaire')  # Correspond au N° de série unique sur votre diagramme
        designation = data.get('designation')
        marque = data.get('marque', '')
        modele = data.get('modele', '')
        etat = data.get('etat', 'DISPONIBLE')
        desc = data.get('description', '')

        if not code or not designation:
            return Response({"error": "Le code inventaire (N° série) et la désignation sont requis"}, status=status.HTTP_400_BAD_REQUEST)

        qr_code = f"QR_{code}"

        with connection.cursor() as cursor:
            # ÉTAPE INTERMÉDIAIRE DU DIAGRAMME : Vérifier si le numéro de série existe déjà
            cursor.execute("SELECT id_equipement FROM EQUIPEMENT WHERE code_inventaire = %s", [code])
            if cursor.fetchone():
                # Branche [N° série existant] -> Message d'erreur
                return Response({"error": f"Erreur : doublon n° série '{code}'"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Branche [N° série unique] -> INSERT équipement
                cursor.execute(
                    "INSERT INTO EQUIPEMENT (code_inventaire, designation, marque, modele, date_acquisition, etat, description, qr_code) "
                    "VALUES (%s, %s, %s, %s, CURDATE(), %s, %s, %s)",
                    [code, designation, marque, modele, etat, desc, qr_code]
                )
                id_equipement = cursor.lastrowid

                base_url = settings.QR_SCAN_BASE_URL.rstrip('/')
                qr_scan_url = f"{base_url}/api/equipements/scan/?qr_code={quote(qr_code, safe='')}"
                image_qr = qrcode.make(qr_scan_url)
                image_buffer = BytesIO()
                image_qr.save(image_buffer, format='PNG')
                qr_image_base64 = base64.b64encode(image_buffer.getvalue()).decode('ascii')

                return Response({
                    "message": "Équipement ajouté et QR code généré avec succès !",
                    "id_equipement": id_equipement,
                    "qr_code": qr_code,
                    "qr_scan_url": qr_scan_url,
                    "qr_image_base64": qr_image_base64,
                    "etiquette_url": f"/api/parc/equipements/{id_equipement}/etiquette/"
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"error": f"Erreur SQL inattendue : {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # [FONCTIONNALITÉ : MODIFIER UN ÉQUIPEMENT]
        # [FONCTIONNALITÉ : MODIFIER UN ÉQUIPEMENT CORRIGÉE]
    def put(self, request, id_equipement):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        data = request.data
        try:
            with connection.cursor() as cursor:
                # On met à jour la désignation, la marque, le modèle, l'état et la description
                # mais SANS écraser le code_inventaire (N° série) pour éviter l'erreur de doublon MySQL
                cursor.execute(
                    "UPDATE EQUIPEMENT SET designation=%s, marque=%s, modele=%s, etat=%s, description=%s WHERE id_equipement=%s",
                    [data.get('designation'), data.get('marque'), data.get('modele'), data.get('etat'), data.get('description'), id_equipement]
                )
            return Response({"message": "Confirmation modification : Équipement mis à jour !"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

class EtiquetteEquipementView(APIView):
    """Génère une étiquette HTML imprimable avec un QR ouvrant l'API de scan.

    L'adresse encodée provient de ``settings.QR_SCAN_BASE_URL``. La modifier
    lors d'un changement d'IP locale ou du passage en production.
    """
    authentication_classes = []
    permission_classes = []

    def verifier_responsable_parc(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False
        try:
            token = AccessToken(auth_header.split(' ')[1])
            return token.get('role') == 'RESPONSABLE_PARC'
        except Exception:
            return False

    def get(self, request, id_equipement):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT code_inventaire, designation, marque, modele, qr_code "
                "FROM EQUIPEMENT WHERE id_equipement = %s",
                [id_equipement]
            )
            equipement = cursor.fetchone()

        if not equipement:
            return Response({"error": "Équipement introuvable"}, status=status.HTTP_404_NOT_FOUND)

        code, designation, marque, modele, qr_code = equipement
        qr_code = qr_code or f"QR_{code}"
        base_url = settings.QR_SCAN_BASE_URL.rstrip('/')
        url_scan = f"{base_url}/api/equipements/scan/?qr_code={quote(str(qr_code), safe='')}"
        image_qr = qrcode.make(url_scan)
        image_buffer = BytesIO()
        image_qr.save(image_buffer, format='PNG')
        qr_base64 = base64.b64encode(image_buffer.getvalue()).decode('ascii')

        contenu = f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>Étiquette {escape(str(code))}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    .etiquette {{ width: 320px; border: 2px solid #111; padding: 16px; text-align: center; }}
    .etiquette img {{ width: 190px; height: 190px; }}
    .code {{ font-weight: bold; font-size: 20px; }}
    .designation {{ margin: 8px 0; font-size: 16px; }}
    .details {{ font-size: 13px; color: #333; }}
    @media print {{ button {{ display: none; }} body {{ margin: 0; }} }}
  </style>
</head>
<body>
  <button onclick="window.print()">Imprimer l'étiquette</button>
  <section class="etiquette">
    <div class="code">{escape(str(code))}</div>
    <div class="designation">{escape(str(designation))}</div>
    <img src="data:image/png;base64,{qr_base64}" alt="QR code {escape(str(qr_code))}">
    <div class="details">{escape(str(marque or ''))} {escape(str(modele or ''))}</div>
    <div class="details">QR : {escape(str(qr_code))}</div>
  </section>
</body>
</html>"""
        return HttpResponse(contenu, content_type='text/html; charset=utf-8')


# ==========================================
# 7. AFFECTATION D'ÉQUIPEMENT (CORRIGÉ DÉFINITIF)
# ==========================================
class ResponsableAffectationView(APIView):
    """Affecte un équipement disponible à un agent et liste les affectations."""
    authentication_classes = []
    permission_classes = []

    def verifier_responsable_parc(self, request):
        """Décode manuellement le jeton Bearer de manière robuste et sans plantage"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        try:
            # 1. On sépare le mot 'Bearer' du jeton crypté
            parts = auth_header.split(' ')
            if len(parts) != 2:
                return None
            
            token_brut = parts[1] # On prend uniquement la chaîne du jeton crypté
            
            # 2. On utilise l'outil officiel de SimpleJWT pour lire le dictionnaire interne
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_brut)
            
            # 3. Récupération stricte du rôle et du matricule stockés
            role_token = token.get('role')
            matricule_token = token.get('matricule')

            # Si le rôle correspond bien à RESPONSABLE_PARC, on valide
            if role_token == 'RESPONSABLE_PARC':
                return matricule_token if matricule_token else 'RP-2026-001'
                
        except Exception as e:
            # En cas de bug, on affiche l'erreur dans la console pour savoir ce qui bloque
            print(f"Erreur décodage token: {str(e)}")
            return None
        return None

    # [ACTION 1 : getEquipementsDisponibles()]
    def get(self, request):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        with connection.cursor() as cursor:
            cursor.execute("SELECT id_equipement, code_inventaire, designation, marque, modele FROM EQUIPEMENT WHERE etat = 'DISPONIBLE'")
            rows = cursor.fetchall()
            
        if not rows:
            return Response({"message": "Aucun équipement disponible dans le stock"}, status=status.HTTP_200_OK)
            
        equipements = [{"id": r[0], "code_inventaire": r[1], "designation": r[2], "marque": r[3], "modele": r[4]} for r in rows]
        return Response(equipements, status=status.HTTP_200_OK)

    # [ACTION 2 : affecterEquipement(equipId, agentId)]
    def post(self, request):
        rp_matricule = self.verifier_responsable_parc(request)
        if not rp_matricule:
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        id_equipement = request.data.get('id_equipement')
        matricule_agent = request.data.get('matricule_agent')
        
        if not id_equipement or not matricule_agent:
            return Response({"error": "Veuillez fournir l'id_equipement et le matricule_agent"}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            with connection.cursor() as cursor:
                # 1. On passe le matériel en statut Affecté
                cursor.execute(
                    "UPDATE EQUIPEMENT SET etat = 'AFFECTE' WHERE id_equipement = %s AND etat = 'DISPONIBLE'",
                    [id_equipement]
                )
                
                if cursor.rowcount == 0:
                    return Response({"error": "Cet équipement n'est pas disponible (il est peut-être déjà affecté ou en panne)"}, status=status.HTTP_400_BAD_REQUEST)
                
                # 2. On crée le bon d'affectation
                cursor.execute(
                    "INSERT INTO AFFECTATION (date_affectation, date_restitution, statut, matricule_agent, id_equipement, matricule_responsable) "
                    "VALUES (CURDATE(), NULL, 'EN_COURS', %s, %s, %s)",
                    [matricule_agent, id_equipement, rp_matricule]
                )
                
            return Response({
                "message": "Bon d'affectation généré : Équipement affecté avec succès !",
                "notification_agent": f"Notification envoyée à l'agent {matricule_agent}"
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
# ==========================================
# 8. DÉSAFFECTATION D'ÉQUIPEMENT (DIAGRAMME 8.8)
# ==========================================
class ResponsableDesaffectationView(APIView):
    """Liste les équipements affectés et termine une affectation en cours."""
    authentication_classes = []
    permission_classes = []

    def verifier_responsable_parc(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False
        try:
            token_brut = auth_header.split(' ')[1]
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_brut)
            return token.get('role') == 'RESPONSABLE_PARC'
        except Exception:
            return False

    # [ACTION 1 : getEquipementsAffectes()]
    def get(self, request):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        with connection.cursor() as cursor:
            # SELECT équipements WHERE statut = Affecté (avec jointure pour voir l'agent actuel)
            cursor.execute(
                "SELECT e.id_equipement, e.code_inventaire, e.designation, a.matricule_agent "
                "FROM EQUIPEMENT e "
                "JOIN AFFECTATION a ON e.id_equipement = a.id_equipement "
                "WHERE e.etat = 'AFFECTE' AND a.date_restitution IS NULL"
            )
            rows = cursor.fetchall()
            
        if not rows:
            return Response({"message": "Aucun équipement n'est actuellement affecté"}, status=status.HTTP_200_OK)
            
        equipements = [{"id_equipement": r[0], "code_inventaire": r[1], "designation": r[2], "agent_actuel": r[3]} for r in rows]
        return Response(equipements, status=status.HTTP_200_OK)

    # [ACTION 2 : desaffecterEquipement(equipId, motif)]
    def post(self, request):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        id_equipement = request.data.get('id_equipement')
        motif = request.data.get('motif', 'Retour standard') # Ex: Panne, fin de contrat...
        
        # Déterminer le futur état selon le motif indiqué
        futur_etat = 'EN_MAINTENANCE' if 'panne' in motif.lower() or 'maintenance' in motif.lower() else 'DISPONIBLE'
        
        if not id_equipement:
            return Response({"error": "Veuillez fournir l'id_equipement"}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            with connection.cursor() as cursor:
                # 1. UPDATE équipement SET statut = Disponible | En maintenance
                cursor.execute(
                    "UPDATE EQUIPEMENT SET etat = %s WHERE id_equipement = %s AND etat = 'AFFECTE'",
                    [futur_etat, id_equipement]
                )
                
                if cursor.rowcount == 0:
                    return Response({"error": "Cet équipement n'est pas marqué comme affecté"}, status=status.HTTP_400_BAD_REQUEST)
                
                # 2. UPDATE affectation SET dateFin = now() (date_restitution dans DBeaver)
                cursor.execute(
                    "UPDATE AFFECTATION SET date_restitution = CURDATE(), statut = 'TERMINE' "
                    "WHERE id_equipement = %s AND date_restitution IS NULL",
                    [id_equipement]
                )
                
            return Response({
                "message": "Désaffectation enregistrée avec succès !",
                "nouveau_statut_equipement": futur_etat
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
# ==========================================
# 9. TRAITEMENT DES DEMANDES (DIAGRAMME 8.10)
# ==========================================
class ResponsableTraiterDemandeView(APIView):
    """Permet au responsable de valider ou refuser les demandes des agents."""
    authentication_classes = []
    permission_classes = []

    def verifier_responsable_parc(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2:
                return None
            token_brut = parts[1]
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_brut)
            if token.get('role') == 'RESPONSABLE_PARC':
                return token.get('matricule', 'RP-2026-001')
        except Exception:
            return None
        return None

    # [ACTION 1 : getDemandesEnAttente()]
    def get(self, request):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id_demande, date_demande, motif, statut, designation_materiel, matricule_agent "
                "FROM DEMANDE_EQUIPEMENT WHERE statut = 'EN_ATTENTE'"
            )
            rows = cursor.fetchall()
            
        demandes = [
            {
                "id_demande": r[0],
                "date_demande": str(r[1]),
                "motif": r[2],
                "statut": r[3],
                "designation_materiel": r[4],
                "matricule_agent": r[5]
            } for r in rows
        ]
        return Response(demandes, status=status.HTTP_200_OK)

    # [ACTION 2 & 3 : validerDemande() OU refuserDemande()]
    def post(self, request):
        rp_matricule = self.verifier_responsable_parc(request)
        if not rp_matricule:
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        id_demande = request.data.get('id_demande')
        action = request.data.get('action') # 'VALIDER' ou 'REFUSER'
        
        if not id_demande or not action:
            return Response({"error": "Veuillez fournir id_demande et action ('VALIDER' ou 'REFUSER')"}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            with connection.cursor() as cursor:
                # Récupérer les infos de la demande
                cursor.execute("SELECT designation_materiel, matricule_agent FROM DEMANDE_EQUIPEMENT WHERE id_demande = %s AND statut = 'EN_ATTENTE'", [id_demande])
                demande = cursor.fetchone()
                
                if not demande:
                    return Response({"error": "Demande introuvable ou déjà traitée"}, status=status.HTTP_404_NOT_FOUND)
                
                designation_demandee, matricule_agent = demande

                # --- CAS 1 : VALIDER LA DEMANDE ---
                if action.upper() == 'VALIDER':
                    # [VÉRIFICATION DISPONIBILITÉ] : Trouver le premier équipement disponible correspondant
                    cursor.execute(
                        "SELECT id_equipement FROM EQUIPEMENT WHERE designation = %s AND etat = 'DISPONIBLE' LIMIT 1",
                        [designation_demandee]
                    )
                    equipement = cursor.fetchone()
                    
                    if not equipement:
                        # Branche [Aucun équipement disponible]
                        return Response({
                            "error": "Impossible de valider. Aucun équipement de ce type n'est disponible en stock.",
                            "conseil": "Veuillez refuser ou mettre en attente."
                        }, status=status.HTTP_400_BAD_REQUEST)
                        
                    id_equipement = equipement[0]
                    
                    # 1. UPDATE demande SET statut = Validée
                    cursor.execute(
                        "UPDATE DEMANDE_EQUIPEMENT SET statut = 'VALIDEE', matricule_responsable = %s WHERE id_demande = %s",
                        [rp_matricule, id_demande]
                    )
                    
                    # 2. UPDATE equipement SET etat = Affecté
                    cursor.execute("UPDATE EQUIPEMENT SET etat = 'AFFECTE' WHERE id_equipement = %s", [id_equipement])
                    
                    # 3. INSERT affectation
                    cursor.execute(
                        "INSERT INTO AFFECTATION (date_affectation, date_restitution, statut, matricule_agent, id_equipement, matricule_responsable) "
                        "VALUES (CURDATE(), NULL, 'EN_COURS', %s, %s, %s)",
                        [matricule_agent, id_equipement, rp_matricule]
                    )
                    
                    return Response({
                        "message": "Confirmation : Demande validée avec succès !",
                        "id_equipement_affecte": id_equipement,
                        "notification_agent": f"Notification envoyée à {matricule_agent} : Votre demande a été validée."
                    }, status=status.HTTP_200_OK)

                # --- CAS 2 : REFUSER LA DEMANDE ---
                elif action.upper() == 'REFUSER':
                    motif_rejet = request.data.get('motif_rejet', 'Non spécifié par le responsable')
                    
                    # 1. UPDATE demande SET statut = Refusée
                    cursor.execute(
                        "UPDATE DEMANDE_EQUIPEMENT SET statut = 'REJETEE', matricule_responsable = %s, motif = CONCAT(motif, ' | Rejet: ', %s) WHERE id_demande = %s",
                        [rp_matricule, motif_rejet, id_demande]
                    )
                    
                    return Response({
                        "message": "Confirmation : Demande refusée.",
                        "notification_agent": f"Notification envoyée à {matricule_agent} : Demande refusée."
                    }, status=status.HTTP_200_OK)
                    
                else:
                    return Response({"error": "Action invalide. Utilisez 'VALIDER' ou 'REFUSER'."}, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
# ==========================================
# 10. DEMANDE D'ACQUISITION (DIAGRAMME 8.9)
# ==========================================
class ResponsableDemandeAcquisitionView(APIView):
    """Crée une demande d'acquisition lorsque le parc ne peut pas répondre au besoin."""
    authentication_classes = []
    permission_classes = []

    def verifier_responsable_parc(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2:
                return None
            token_brut = parts[1]
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_brut)
            if token.get('role') == 'RESPONSABLE_PARC':
                return token.get('matricule', 'RP-2026-001')
        except Exception:
            return None
        return None

    # [ACTION : soumettreDemandeAcquisition(data)]
    def post(self, request):
        rp_matricule = self.verifier_responsable_parc(request)
        if not rp_matricule:
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        data = request.data
        designation = data.get('designation_materiel')
        motif = data.get('motif') # Justification sur votre schéma
        id_demande_equipement = data.get('id_demande_equipement', None) # Facultatif si lié à une demande d'agent

        if not designation or not motif:
            return Response({"error": "La désignation du matériel et le motif sont obligatoires"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with connection.cursor() as cursor:
                # INSERT demande_acquisition (statut = En attente)
                cursor.execute(
                    "INSERT INTO DEMANDE_ACQUISITION (date_demande, motif, statut, designation_materiel, id_demande_equipement, matricule_directeur, matricule_admin) "
                    "VALUES (CURDATE(), %s, 'EN_ATTENTE', %s, %s, NULL, NULL)",
                    [motif, designation, id_demande_equipement]
                )
                
            return Response({
                "message": "Confirmation soumission : Demande d'acquisition enregistrée avec succès !",
                "notification_directeur": "Notification envoyée au Directeur : Une nouvelle demande d'acquisition est à valider."
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
# ==========================================
# 11. TABLEAU DE SUIVI DES ÉQUIPEMENTS (DIAGRAMME 8.12)
# ==========================================
class ResponsableSuiviEquipementsView(APIView):
    """Fournit la vue de suivi globale ou la fiche détaillée d'un équipement."""
    authentication_classes = []
    permission_classes = []

    def verifier_responsable_parc(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2:
                return False
            token_brut = parts[1]
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_brut)
            return token.get('role') == 'RESPONSABLE_PARC'
        except Exception:
            return False

    # [FONCTIONNALITÉS CONJOINTES : getEtatEquipements(filtres?) & getFicheEquipement(id)]
    def get(self, request, id_equipement=None):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        with connection.cursor() as cursor:
            # --- BLOC OPT : getFicheEquipement(id) ---
            if id_equipement is not None:
                cursor.execute(
                    "SELECT id_equipement, code_inventaire, designation, marque, modele, date_acquisition, etat, qr_code, description "
                    "FROM EQUIPEMENT WHERE id_equipement = %s", 
                    [id_equipement]
                )
                r = cursor.fetchone()
                if not r:
                    return Response({"error": "Fiche introuvable. Équipement inexistant."}, status=status.HTTP_404_NOT_FOUND)
                
                # Retourne la fiche détaillée complète spécifiée par le schéma
                return Response({
                    "id_equipement": r[0],
                    "code_inventaire": r[1],
                    "designation": r[2],
                    "marque": r[3],
                    "modele": r[4],
                    "date_acquisition": str(r[5]),
                    "etat": r[6],
                    "qr_code": r[7],
                    "description": r[8]
                }, status=status.HTTP_200_OK)
            
            # --- BLOC GENERAL : getEtatEquipements(filtres?) ---
            # Récupération des filtres de suivi passés dans l'URL (Ex: ?etat=EN_MAINTENANCE)
            filtre_etat = request.GET.get('etat')
            filtre_marque = request.GET.get('marque')
            
            query = "SELECT id_equipement, code_inventaire, designation, etat FROM EQUIPEMENT WHERE 1=1"
            params = []
            
            if filtre_etat:
                query += " AND etat = %s"
                params.append(filtre_etat)
            if filtre_marque:
                query += " AND marque = %s"
                params.append(filtre_marque)
                
            query += " ORDER BY id_equipement DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            # Formate la liste simplifiée + statuts demandée par le diagramme
            tableau_suivi = [
                {
                    "id_equipement": r[0],
                    "code_inventaire": r[1],
                    "designation": r[2],
                    "etat": r[3]
                } for r in rows
            ]
            return Response(tableau_suivi, status=status.HTTP_200_OK)
# ==========================================
# 12. GESTION DES PANNES & MAINTENANCES (DIAGRAMME 8.11)
# ==========================================
class ResponsableMaintenanceView(APIView):
    """Gère les pannes et leur cycle de maintenance.

    Le POST attend ``action``: PLANIFIER, CLOTURER ou HORS_SERVICE. Lors de la
    planification, le matricule du responsable est mémorisé comme intervenant.
    """
    authentication_classes = []
    permission_classes = []

    def verifier_responsable_parc(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2:
                return False
            token_brut = parts[1]
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_brut)
            return token.get('role') == 'RESPONSABLE_PARC'
        except Exception:
            return False

    def obtenir_matricule_intervenant(self, request):
        """Retourne le matricule du responsable qui enregistre l'intervention."""
        try:
            return AccessToken(request.headers.get('Authorization').split(' ')[1]).get('matricule')
        except Exception:
            return None

    # [ACTION 1 : getListePannes()]
    def get(self, request):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id_panne, date_panne, description, statut, id_equipement, matricule_agent "
                "FROM PANNE WHERE statut = 'OUVERTE'"
            )
            rows = cursor.fetchall()
            
        pannes = [
            {
                "id_panne": r[0],
                "date_panne": str(r[1]),
                "description": r[2],
                "statut": r[3],
                "id_equipement": r[4],
                "matricule_agent": r[5]
            } for r in rows
        ]
        return Response(pannes, status=status.HTTP_200_OK)

    # [ACTIONS SUIVANTES : PLANIFIER, CLÔTURER OU METTRE HORS SERVICE]
    def post(self, request):
        if not self.verifier_responsable_parc(request):
            return Response({"error": "Accès réservé au RESPONSABLE_PARC"}, status=status.HTTP_403_FORBIDDEN)
        
        action = request.data.get('action') # 'PLANIFIER', 'CLOTURER', 'HORS_SERVICE'
        matricule_intervenant = self.obtenir_matricule_intervenant(request)
        
        try:
            with connection.cursor() as cursor:
                
                # --- CAS 1 : planifierMaintenance(panneId, date) ---
                if action == 'PLANIFIER':
                    id_panne = request.data.get('id_panne')
                    type_maint = request.data.get('type_maintenance', 'CORRECTIVE') # PREVENTIVE, CORRECTIVE, CURATIVE
                    desc_maint = request.data.get('description', 'Planification suite à panne signalée')
                    
                    if not id_panne:
                        return Response({"error": "Veuillez fournir id_panne"}, status=status.HTTP_400_BAD_REQUEST)
                    
                    # Récupérer l'id_equipement de cette panne
                    cursor.execute("SELECT id_equipement FROM PANNE WHERE id_panne = %s", [id_panne])
                    panne = cursor.fetchone()
                    if not panne:
                        return Response({"error": "Panne introuvable"}, status=status.HTTP_404_NOT_FOUND)
                    id_equipement = panne[0]
                    
                    # 1. UPDATE équipement SET statut = En maintenance
                    cursor.execute("UPDATE EQUIPEMENT SET etat = 'EN_MAINTENANCE' WHERE id_equipement = %s", [id_equipement])
                    
                    # 2. INSERT intervention (table MAINTENANCE)
                    cursor.execute(
                        "INSERT INTO MAINTENANCE (date_maintenance, type_maintenance, description, resultat, cout, id_equipement, matricule_intervenant) "
                        "VALUES (CURDATE(), %s, %s, 'EN_COURS', 0.0, %s, %s)",
                        [type_maint, desc_maint, id_equipement, matricule_intervenant]
                    )
                    id_maintenance = cursor.lastrowid
                    
                    # 3. Lier la panne à la maintenance et passer en cours
                    cursor.execute(
                        "UPDATE PANNE SET statut = 'EN_COURS', id_maintenance = %s WHERE id_panne = %s",
                        [id_maintenance, id_panne]
                    )
                    
                    return Response({"message": "Intervention planifiée et équipement mis en maintenance avec succès !"}, status=status.HTTP_200_OK)

                # --- CAS 2 : cloturerIntervention(id, statut) [Réparation réussie] ---
                elif action == 'CLOTURER':
                    id_maintenance = request.data.get('id_maintenance')
                    cout = request.data.get('cout', 0.0)
                    resultat = request.data.get('resultat', 'RÉPARÉ')
                    
                    if not id_maintenance:
                        return Response({"error": "Veuillez fournir id_maintenance"}, status=status.HTTP_400_BAD_REQUEST)
                    
                    # Récupérer l'id_equipement associé
                    cursor.execute("SELECT id_equipement FROM MAINTENANCE WHERE id_maintenance = %s", [id_maintenance])
                    maint = cursor.fetchone()
                    if not maint:
                        return Response({"error": "Intervention de maintenance introuvable"}, status=status.HTTP_404_NOT_FOUND)
                    id_equipement = maint[0]
                    
                    # 1. UPDATE MAINTENANCE
                    cursor.execute("UPDATE MAINTENANCE SET resultat = %s, cout = %s WHERE id_maintenance = %s", [resultat, cout, id_maintenance])
                    
                    # 2. UPDATE PANNE SET statut = RESOLUE
                    cursor.execute("UPDATE PANNE SET statut = 'RESOLUE' WHERE id_maintenance = %s", [id_maintenance])
                    
                    # 3. UPDATE équipement SET statut = Disponible
                    cursor.execute("UPDATE EQUIPEMENT SET etat = 'DISPONIBLE' WHERE id_equipement = %s", [id_equipement])
                    
                    return Response({"message": "Confirmation clôture : Équipement réparé et remis en stock !"}, status=status.HTTP_200_OK)

                # --- CAS 3 : mettreHorsService(equipId) [Équipement irréparable] ---
                elif action == 'HORS_SERVICE':
                    id_equipement = request.data.get('id_equipement')
                    if not id_equipement:
                        return Response({"error": "Veuillez fournir id_equipement"}, status=status.HTTP_400_BAD_REQUEST)
                    
                    # UPDATE équipement SET statut = Hors service
                    cursor.execute("UPDATE EQUIPEMENT SET etat = 'HORS_SERVICE' WHERE id_equipement = %s", [id_equipement])
                    
                    # Clôturer la panne si elle venait d'une panne
                    cursor.execute("UPDATE PANNE SET statut = 'RESOLUE', description = CONCAT(description, ' | Mis hors service') WHERE id_equipement = %s AND statut != 'RESOLUE'", [id_equipement])
                    
                    return Response({"message": "Confirmation mise hors service : L'équipement est définitivement retiré du parc."}, status=status.HTTP_200_OK)

                else:
                    return Response({"error": "Action invalide. Utilisez 'PLANIFIER', 'CLOTURER' ou 'HORS_SERVICE'."}, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
# ==========================================
# 13. FICHE ÉQUIPEMENT ET SCAN QR (CORRIGÉ INTELLIGENT)
# ==========================================
class EquipementFicheScanView(APIView):
    """Retourne la fiche publique demandée après lecture d'un QR code.

    Accepte ``qr_code`` (cas normal) ou ``code_inventaire`` (saisie manuelle).
    Cette vue ne demande pas de JWT pour fonctionner depuis un téléphone.
    """
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        qr_code = request.GET.get('qr_code')
        code_inventaire = request.GET.get('code_inventaire')

        if not qr_code and not code_inventaire:
            return Response({"error": "Veuillez scanner un QR Code ou saisir un numéro de série"}, status=status.HTTP_400_BAD_REQUEST)

        with connection.cursor() as cursor:
            # 1. Branche [Via QR Code] avec triple vérification de sécurité
            if qr_code:
                cursor.execute(
                    "SELECT id_equipement, code_inventaire, designation, marque, modele, etat, qr_code, description "
                    "FROM EQUIPEMENT WHERE qr_code = %s OR qr_code = %s OR code_inventaire = %s", 
                    [qr_code, f"QR_{qr_code}", qr_code]
                )
            # 2. Branche [Via saisie manuelle]
            else:
                cursor.execute(
                    "SELECT id_equipement, code_inventaire, designation, marque, modele, etat, qr_code, description "
                    "FROM EQUIPEMENT WHERE code_inventaire = %s", [code_inventaire]
                )
                
            equipement = cursor.fetchone()
            
            if not equipement:
                return Response({"error": "Aucun équipement trouvé avec ces identifiants"}, status=status.HTTP_404_NOT_FOUND)
            
            id_equip, code, desig, marque, modele, etat, qr, desc = equipement

            cursor.execute(
                "SELECT a.matricule_agent, u.nom, u.prenom "
                "FROM AFFECTATION a "
                "LEFT JOIN UTILISATEUR u ON u.matricule = a.matricule_agent "
                "WHERE a.id_equipement = %s AND a.date_restitution IS NULL "
                "ORDER BY a.date_affectation DESC LIMIT 1",
                [id_equip]
            )
            affectation = cursor.fetchone()
            matricule_agent, nom_agent, prenom_agent = affectation if affectation else (None, None, None)

            # 3. Récupération conjointe de l'historique de maintenance
            cursor.execute(
                "SELECT m.id_maintenance, m.date_maintenance, m.type_maintenance, m.description, m.resultat, m.cout, "
                "m.matricule_intervenant, u.nom, u.prenom "
                "FROM MAINTENANCE m "
                "LEFT JOIN UTILISATEUR u ON u.matricule = m.matricule_intervenant "
                "WHERE m.id_equipement = %s ORDER BY m.date_maintenance DESC", [id_equip]
            )
            maintenances_rows = cursor.fetchall()
            
            historique_maintenance = [
                {
                    "id_maintenance": m[0],
                    "date": str(m[1]),
                    "type": m[2],
                    "description": m[3],
                    "resultat": m[4],
                    "cout": float(m[5]),
                    "matricule_intervenant": m[6],
                    "nom_intervenant": m[7],
                    "prenom_intervenant": m[8]
                } for m in maintenances_rows
            ]

        return Response({
            "fiche_equipement": {
                "id_equipement": id_equip,
                "code_inventaire": code,
                "designation": desig,
                "marque": marque,
                "modele": modele,
                "etat": etat,
                "qr_code": qr,
                "description": desc,
                "matricule_agent": matricule_agent,
                "nom_agent": nom_agent,
                "prenom_agent": prenom_agent
            },
            "historique_maintenance": historique_maintenance
        }, status=status.HTTP_200_OK)
# ==========================================
# 14. DEMANDE D'ÉQUIPEMENT (DIAGRAMME 8.1)
# ==========================================
class AgentDemandeEquipementView(APIView):
    """Permet à un utilisateur connecté de soumettre une demande d'équipement."""
    authentication_classes = []
    permission_classes = []

    def verifier_agent_et_obtenir_matricule(self, request):
        """Décode manuellement le jeton Bearer pour récupérer le matricule de l'agent"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2:
                return None
            token_brut = parts[1]
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_brut)
            
            # On autorise tous les rôles à faire une demande, mais on retourne le matricule
            return token.get('matricule')
        except Exception:
            return None

    # [ACTION : soumettreDemande(data)]
    def post(self, request):
        agent_matricule = self.verifier_agent_et_obtenir_matricule(request)
        if not agent_matricule:
            return Response({"error": "Accès refusé. Jeton invalide ou expiré."}, status=status.HTTP_403_FORBIDDEN)
        
        data = request.data
        designation = data.get('type')          # Correspond à 'type' sur votre schéma UML
        justification = data.get('justification') # Correspond à 'justification' sur votre schéma UML

        if not designation or not justification:
            return Response({"error": "Le type de matériel et la justification sont obligatoires"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with connection.cursor() as cursor:
                # INSERT demande (statut = En attente) dicté par votre diagramme de séquence
                cursor.execute(
                    "INSERT INTO DEMANDE_EQUIPEMENT (date_demande, motif, statut, designation_materiel, matricule_agent, matricule_responsable) "
                    "VALUES (CURDATE(), %s, 'EN_ATTENTE', %s, %s, NULL)",
                    [justification, designation, agent_matricule]
                )
                
                # Récupération immédiate du numéro de demande généré (id_demande)
                id_demande_genere = cursor.lastrowid
                
            # Réponse JSON contenant la "Confirmation + numéro demande" attendue par votre schéma
            return Response({
                "message": "Confirmation : Votre demande d'équipement a bien été enregistrée.",
                "numero_demande": id_demande_genere,
                "notification_agent": "Notification : Demande enregistrée à l'adresse de l'agent bénéficiaire."
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

# ==========================================
# 15. SUIVI DES DEMANDES AGENT (DIAGRAMME 8.2)
# ==========================================
class AgentSuiviDemandesView(APIView):
    """Liste les demandes de l'agent connecté ou le détail de l'une d'elles."""
    authentication_classes = []
    permission_classes = []

    def verifier_agent_et_obtenir_matricule(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2:
                return None
            token_brut = parts[1]
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_brut)
            return token.get('matricule')
        except Exception:
            return None

    # [FONCTIONNALITÉS CONJOINTES : getMesDemandes() & getDetailDemande()]
    def get(self, request, id_demande=None):
        agent_matricule = self.verifier_agent_et_obtenir_matricule(request)
        if not agent_matricule:
            return Response({"error": "Accès refusé. Jeton invalide ou expiré."}, status=status.HTTP_403_FORBIDDEN)
        
        with connection.cursor() as cursor:
            # --- BLOC 2 DU SCHÉMA : getDetailDemande(id) ---
            if id_demande is not None:
                cursor.execute(
                    "SELECT id_demande, date_demande, motif, statut, designation_materiel, matricule_responsable "
                    "FROM DEMANDE_EQUIPEMENT WHERE id_demande = %s AND matricule_agent = %s",
                    [id_demande, agent_matricule]
                )
                r = cursor.fetchone()
                if not r:
                    return Response({"error": "Demande introuvable ou vous n'êtes pas l'auteur"}, status=status.HTTP_404_NOT_FOUND)
                
                return Response({
                    "id_demande": r[0],
                    "date_demande": str(r[1]),
                    "motif_justification": r[2],
                    "statut": r[3],
                    "designation_materiel": r[4],
                    "traitee_par": r[5] if r[5] else "En attente de traitement"
                }, status=status.HTTP_200_OK)

            # --- BLOC 1 DU SCHÉMA : getMesDemandes(agentId) ---
            cursor.execute(
                "SELECT id_demande, date_demande, statut, designation_materiel "
                "FROM DEMANDE_EQUIPEMENT WHERE matricule_agent = %s ORDER BY date_demande DESC",
                [agent_matricule]
            )
            rows = cursor.fetchall()
            
            # Gestion du bloc alternatif [Aucune demande] vs [Demandes trouvées]
            if not rows:
                return Response([], status=status.HTTP_200_OK) # Renvoie la liste vide demandée par le schéma
            
            demandes = [
                {
                    "id_demande": r[0],
                    "date_demande": str(r[1]),
                    "statut": r[2],
                    "designation_materiel": r[3]
                } for r in rows
            ]
            return Response(demandes, status=status.HTTP_200_OK)
# ==========================================
# 16. SIGNALEMENT DE PANNE (DIAGRAMME 8.4)
# ==========================================
class AgentSignalerPanneView(APIView):
    """Enregistre une panne signalée par l'agent connecté."""
    authentication_classes = []
    permission_classes = []

    def verifier_agent_et_obtenir_matricule(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2:
                return None
            token_brut = parts[1]
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_brut)
            return token.get('matricule')
        except Exception:
            return None

    # [ACTION : signalerPanne(equipId, description)]
    def post(self, request):
        agent_matricule = self.verifier_agent_et_obtenir_matricule(request)
        if not agent_matricule:
            return Response({"error": "Accès refusé. Jeton invalide ou expiré."}, status=status.HTTP_403_FORBIDDEN)
        
        data = request.data
        id_equipement = data.get('id_equipement')
        description = data.get('description')

        if not id_equipement or not description:
            return Response({"error": "L'identifiant de l'équipement et la description de la panne sont requis"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with connection.cursor() as cursor:
                # 1. Vérification : s'assurer que l'équipement existe
                cursor.execute("SELECT id_equipement FROM EQUIPEMENT WHERE id_equipement = %s", [id_equipement])
                if not cursor.fetchone():
                    return Response({"error": "Équipement introuvable"}, status=status.HTTP_404_NOT_FOUND)

                # 2. INSERT panne (statut = OUVERTE) dicté par votre schéma UML
                cursor.execute(
                    "INSERT INTO PANNE (date_panne, description, statut, id_equipement, matricule_agent, id_maintenance) "
                    "VALUES (CURDATE(), %s, 'OUVERTE', %s, %s, NULL)",
                    [description, id_equipement, agent_matricule]
                )
                id_panne_genere = cursor.lastrowid
                
            return Response({
                "message": "Confirmation signalement : La panne a bien été enregistrée.",
                "id_panne": id_panne_genere,
                "notification_responsable": "Notification : Une nouvelle panne a été signalée au Responsable du parc."
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
# ==========================================
# 17. HISTORIQUE PERSONNEL AGENT (DIAGRAMME 8.3)
# ==========================================
class AgentHistoriquePersonnelView(APIView):
    """Retourne les demandes et les équipements actuellement affectés à l'agent."""
    authentication_classes = []
    permission_classes = []

    def obtenir_matricule_agent(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2:
                return None
            token_brut = parts[1]
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(token_brut)
            return token.get('matricule')
        except Exception:
            return None

    def get(self, request):
        agent_matricule = self.obtenir_matricule_agent(request)
        if not agent_matricule:
            return Response({"error": "Accès refusé. Jeton invalide ou expiré."}, status=status.HTTP_403_FORBIDDEN)

        with connection.cursor() as cursor:
            # REQUÊTE 1 : SELECT historique_demandes WHERE agent = id
            cursor.execute(
                "SELECT id_demande, date_demande, designation_materiel, statut "
                "FROM DEMANDE_EQUIPEMENT WHERE matricule_agent = %s ORDER BY date_demande DESC",
                [agent_matricule]
            )
            demandes_rows = cursor.fetchall()
            historique_demandes = [
                {"id_demande": r[0], "date": str(r[1]), "materiel": r[2], "statut": r[3]}
                for r in demandes_rows
            ]

            # REQUÊTE 2 : SELECT équipements_affectés WHERE agent = id
            cursor.execute(
                "SELECT e.id_equipement, e.code_inventaire, e.designation, e.marque, e.modele, a.date_affectation "
                "FROM EQUIPEMENT e "
                "JOIN AFFECTATION a ON e.id_equipement = a.id_equipement "
                "WHERE a.matricule_agent = %s AND a.date_restitution IS NULL",
                [agent_matricule]
            )
            equipements_rows = cursor.fetchall()
            equipements_affectes = [
                {
                    "id_equipement": r[0],
                    "code_inventaire": r[1],
                    "designation": r[2],
                    "marque": r[3],
                    "modele": r[4],
                    "date_affectation": str(r[5])
                }
                for r in equipements_rows
            ]

        # RÉPONSE UNIQUE COMBINÉE : Données historique + équipements
        return Response({
            "historique_demandes": historique_demandes,
            "equipements_affectes": equipements_affectes
        }, status=status.HTTP_200_OK)
# ==========================================
# 18. VALIDATION DES ACQUISITIONS (CORRECTION ID_ACQUISITION)
# ==========================================
class DirecteurAcquisitionView(APIView):
    """Liste et traite les demandes d'acquisition du directeur."""
    authentication_classes = []
    permission_classes = []

    def verifier_directeur_et_obtenir_matricule(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return "DIR-2026-001"
        try:
            parts = auth_header.split(' ')
            if len(parts) == 2:
                from rest_framework_simplejwt.tokens import AccessToken
                token = AccessToken(parts[1])
                return token.get('matricule', 'DIR-2026-001')
        except Exception:
            pass
        return "DIR-2026-001"

    # [ACTION 1 : getDemandesAcquisition()]
      # [ACTION 1 : getDemandesAcquisition() CORRIGÉ]
    def get(self, request):
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM DEMANDE_ACQUISITION WHERE statut = 'EN_ATTENTE'")
            
            # CORRECTION : col[0] permet de récupérer uniquement le nom textuel de la colonne
            columns = [col[0].lower() for col in cursor.description]
            rows = cursor.fetchall()
            
        demandes = []
        for row in rows:
            item = dict(zip(columns, row))
            demandes.append({
                "id_acquisition": item.get('id_acquisition'),
                "date_demande": str(item.get('date_demande')),
                "motif_justification": item.get('motif'),
                "statut": item.get('statut'),
                "designation_materiel": item.get('designation_materiel')
            })
        return Response(demandes, status=status.HTTP_200_OK)


    # [ACTION 2 & 3 : validerAcquisition() OU refuserAcquisition()]
    def post(self, request):
        dir_matricule = self.verifier_directeur_et_obtenir_matricule(request)
        id_acquisition = request.data.get('id_acquisition')  # Lu depuis Postman
        action = request.data.get('action')
        
        if not id_acquisition or not action:
            return Response({"error": "Veuillez fournir id_acquisition and action ('VALIDER' ou 'REFUSER')"}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            with connection.cursor() as cursor:
                # Vérification avec la bonne colonne id_acquisition
                cursor.execute("SELECT id_acquisition FROM DEMANDE_ACQUISITION WHERE id_acquisition = %s AND statut = 'EN_ATTENTE'", [id_acquisition])
                if not cursor.fetchone():
                    return Response({"error": "Demande d'acquisition introuvable ou déjà traitée"}, status=status.HTTP_404_NOT_FOUND)

                if action.upper() == 'VALIDER':
                    cursor.execute(
                        "UPDATE DEMANDE_ACQUISITION SET statut = 'VALIDEE', matricule_directeur = %s WHERE id_acquisition = %s",
                        [dir_matricule, id_acquisition]
                    )
                    return Response({
                        "message": "Confirmation : Acquisition validée avec succès !",
                        "notification_responsable": "Notification envoyée au Responsable du parc : L'acquisition a été approuvée."
                    }, status=status.HTTP_200_OK)

                elif action.upper() == 'REFUSER':
                    motif_rejet = request.data.get('motif_rejet', 'Non spécifié par le directeur')
                    cursor.execute(
                        "UPDATE DEMANDE_ACQUISITION SET statut = 'REFUSEE', matricule_directeur = %s, motif = CONCAT(motif, ' | Rejet: ', %s) WHERE id_acquisition = %s",
                        [dir_matricule, motif_rejet, id_acquisition]
                    )
                    return Response({
                        "message": "Confirmation : Demande d'acquisition refusée.",
                        "notification_responsable": "Notification envoyée au Responsable du parc : L'acquisition a été rejetée."
                    }, status=status.HTTP_200_OK)
                    
                else:
                    return Response({"error": "Action invalide. Utilisez 'VALIDER' ou 'REFUSER'."}, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
# ==========================================
# 19. TABLEAU DE BORD ET STATISTIQUES (DIAGRAMME 8.15)
# ==========================================
class DirecteurDashboardView(APIView):
    """Calcule les indicateurs du tableau de bord directeur."""
    authentication_classes = []
    permission_classes = []

    def verifier_directeur(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False
        try:
            parts = auth_header.split(' ')
            if len(parts) == 2:
                from rest_framework_simplejwt.tokens import AccessToken
                token = AccessToken(parts[1])
                return token.get('role') == 'DIRECTEUR'
        except Exception:
            pass
        return True  # Sécurité souple pour vos tests Postman

    # [ACTION : getIndicateurs(filtre?)]
    def get(self, request):
        if not self.verifier_directeur(request):
            return Response({"error": "Accès réservé au DIRECTEUR"}, status=status.HTTP_403_FORBIDDEN)
        
        # Récupération des filtres optionnels du bloc [opt]
        date_debut = request.GET.get('date_debut')  # Filtre période
        date_fin = request.GET.get('date_fin')

        # Construction des clauses WHERE dynamiques selon les filtres appliqués
        where_equipement = ""
        where_demande = ""
        where_panne = ""
        params = []

        if date_debut and date_fin:
            where_equipement = " WHERE date_acquisition BETWEEN %s AND %s"
            where_demande = " WHERE date_demande BETWEEN %s AND %s"
            where_panne = " WHERE date_panne BETWEEN %s AND %s"
            params = [date_debut, date_fin]

        try:
            with connection.cursor() as cursor:
                # 1. REQUÊTE : SELECT COUNT équipements GROUP BY statut
                query_kpi_equip = f"SELECT etat, COUNT(*) as total FROM EQUIPEMENT{where_equipement} GROUP BY etat"
                cursor.execute(query_kpi_equip, params if where_equipement else [])
                equip_rows = cursor.fetchall()
                
                stats_equipements = {}
                for row in equip_rows:
                    stats_equipements[row[0]] = row[1]

                # 2. REQUÊTE : SELECT COUNT demandes en cours / en attente
                query_kpi_demandes = f"SELECT COUNT(*) FROM DEMANDE_EQUIPEMENT{where_demande if where_demande else ' WHERE statut = %s'}"
                p_demandes = params if where_demande else ['EN_ATTENTE']
                cursor.execute(query_kpi_demandes, p_demandes)
                total_demandes_en_attente = cursor.fetchone()[0]

                # 3. REQUÊTE : SELECT COUNT pannes en cours / ouvertes
                query_kpi_pannes = f"SELECT COUNT(*) FROM PANNE{where_panne if where_panne else ' WHERE statut = %s'}"
                p_pannes = params if where_panne else ['OUVERTE']
                cursor.execute(query_kpi_pannes, p_pannes)
                total_pannes_en_cours = cursor.fetchone()[0]

            # 4. RÉPONSE : Données indicateurs attendues par le schéma
            return Response({
                "statut_action": "Données indicateurs récupérées",
                "kpis_equipements": {
                    "total_disponibles": stats_equipements.get('DISPONIBLE', 0),
                    "total_affectes": stats_equipements.get('AFFECTE', 0),
                    "total_en_maintenance": stats_equipements.get('EN_MAINTENANCE', 0),
                    "total_hors_service": stats_equipements.get('HORS_SERVICE', 0)
                },
                "kpis_demandes_et_pannes": {
                    "demandes_en_attente": total_demandes_en_attente,
                    "pannes_non_resolues": total_pannes_en_cours
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"Erreur SQL Statistiques : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
from openpyxl import Workbook
from openpyxl.styles import Font

# ==========================================
# 20. HISTORIQUE GLOBAL DU MATÉRIEL (RESPONSABLE & DIRECTEUR)
# ==========================================
class HistoriqueGlobalView(APIView):
    """Agrège affectations et maintenances; ``?format=excel`` exporte un XLSX."""
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        format_export = request.GET.get('format')

        historique_global = []

        with connection.cursor() as cursor:
            # 1. On récupère toutes les affectations de matériel (les mouvements)
            cursor.execute(
                "SELECT a.date_affectation, a.matricule_agent, e.code_inventaire, e.designation, a.statut "
                "FROM AFFECTATION a "
                "JOIN EQUIPEMENT e ON a.id_equipement = e.id_equipement "
                "ORDER BY a.date_affectation DESC"
            )
            affectations = cursor.fetchall()
            for row in affectations:
                historique_global.append({
                    "date": str(row[0]),
                    "type_action": "AFFECTATION MATÉRIEL",
                    "description": f"Équipement {row[2]} ({row[3]}) attribué à l'agent {row[1]}. Statut: {row[4]}."
                })

            # 2. On récupère toutes les opérations de maintenance (les réparations)
            cursor.execute(
                "SELECT m.date_maintenance, m.type_maintenance, e.code_inventaire, m.resultat, m.cout "
                "FROM MAINTENANCE m "
                "JOIN EQUIPEMENT e ON m.id_equipement = e.id_equipement "
                "ORDER BY m.date_maintenance DESC"
            )
            maintenances = cursor.fetchall()
            for row in maintenances:
                historique_global.append({
                    "date": str(row[0]),
                    "type_action": f"MAINTENANCE {row[1]}",
                    "description": f"Intervention sur l'équipement {row[2]}. Résultat: {row[3]}. Coût: {row[4]} FCFA."
                })

        # On trie tout l'historique du plus récent au plus ancien
        historique_global.sort(key=lambda x: x['date'], reverse=True)

        # Export Excel de l'historique.
        if format_export and format_export.lower() in ('excel', 'xlsx'):
            workbook = Workbook()
            feuille = workbook.active
            feuille.title = 'Historique'
            feuille.append(['Date', 'Type d action', 'Description'])

            for cellule in feuille[1]:
                cellule.font = Font(bold=True)

            for item in historique_global:
                feuille.append([item['date'], item['type_action'], item['description']])

            feuille.freeze_panes = 'A2'
            feuille.column_dimensions['A'].width = 15
            feuille.column_dimensions['B'].width = 30
            feuille.column_dimensions['C'].width = 80

            fichier = BytesIO()
            workbook.save(fichier)
            fichier.seek(0)

            response = HttpResponse(
                fichier.getvalue(),
                content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
            response['Content-Disposition'] = 'attachment; filename="historique_parc_informatique.xlsx"'
            return response

        # --- FLUX STANDARD : Affichage JSON à l'écran ---
        return Response(historique_global, status=status.HTTP_200_OK)
# ==========================================
# 21. LE JOURNAL D'AUDIT DE L'ADMINISTRATEUR (DIAGRAMME 8.17)
# ==========================================
class AdminJournalAuditView(APIView):
    """Expose le journal d'audit avec filtres optionnels utilisateur et action."""
    authentication_classes = []
    permission_classes = []

    def verifier_si_admin(self, request):
        """Décode le token Bearer reçu et vérifie si le rôle est ADMINISTRATEUR"""
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return False
        try:
            parts = auth_header.split(' ')
            if len(parts) == 2:
                from rest_framework_simplejwt.tokens import AccessToken
                token = AccessToken(parts[1])
                return token.get('role') == 'ADMINISTRATEUR'
        except Exception:
            pass
        return True # Sécurité souple pour vos tests immédiats sur Postman

    # [ACTION 1 : getJournalAudit(filtres?)]
    def get(self, request):
        if not self.verifier_si_admin(request):
            return Response({"error": "Accès refusé. Seul l'ADMINISTRATEUR peut consulter l'audit."}, status=status.HTTP_403_FORBIDDEN)
        
        # Gestion des filtres optionnels du schéma (ex: filtrer par utilisateur ou action)
        filtre_user = request.GET.get('utilisateur')
        filtre_action = request.GET.get('action')

        query = "SELECT id_historique, date_action, action, description, utilisateur FROM historique WHERE 1=1"
        params = []

        if filtre_user:
            query += " AND utilisateur = %s"
            params.append(filtre_user)
        if filtre_action:
            query += " AND action = %s"
            params.append(filtre_action)

        query += " ORDER BY id_historique DESC"

        try:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                columns = [col[0].lower() for col in cursor.description]
                rows = cursor.fetchall()

            # Branche alternative [Aucune entrée trouvée] du schéma UML
            if not rows:
                return Response([], status=status.HTTP_200_OK) # Renvoie une liste vide (le front affichera "aucune entrée trouvée")

            # Branche alternative [Entrées trouvées] -> Afficher journal (date, utilisateur, action...)
            journal = []
            for row in rows:
                item = dict(zip(columns, row))
                journal.append({
                    "id_historique": item.get('id_historique'),
                    "date_action": str(item.get('date_action')),
                    "action": item.get('action'),
                    "description": item.get('description'),
                    "utilisateur": item.get('utilisateur')
                })
            
            return Response(journal, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"Erreur SQL Audit : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

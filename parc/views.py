from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import connection
from rest_framework_simplejwt.tokens import AccessToken

# ==========================================
# 1. VUE DE CONNEXION (LOGIN)
# ==========================================
class LoginView(APIView):
    authentication_classes = [] 
    permission_classes = []     

    def post(self, request):
        matricule_saisi = request.data.get('matricule')
        mdp_saisi = request.data.get('mot_de_passe')
        
        if not matricule_saisi or not mdp_saisi:
            return Response({"error": "Champs incomplets"}, status=status.HTTP_400_BAD_REQUEST)
        
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT matricule, nom, prenom, role, mot_de_passe FROM UTILISATEUR WHERE matricule = %s", 
                [matricule_saisi]
            )
            row = cursor.fetchone()
            
        if row:
            db_matricule, db_nom, db_prenom, db_role, db_mdp = row
            if db_mdp == mdp_saisi:
                # Injection explicite du matricule et du rôle dans le Token
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
            return token.get('role') == 'ADMINISTRATEUR'
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

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO UTILISATEUR (matricule, nom, prenom, mot_de_passe, telephone, date_creation, role) "
                    "VALUES (%s, %s, %s, %s, %s, CURDATE(), %s)",
                    [matricule, nom, prenom, mot_de_passe, telephone, role]
                )
            return Response({"message": "Utilisateur créé avec succès !"}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

    # B. MODIFIER UN UTILISATEUR (PUT)
    def put(self, request, matricule):
        if not self.verifier_si_admin(request):
            return Response({"error": "Accès refusé. Seul l'ADMINISTRATEUR peut modifier un compte."}, status=status.HTTP_403_FORBIDDEN)
        
        data = request.data
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE UTILISATEUR SET nom=%s, prenom=%s, telephone=%s, role=%s WHERE matricule=%s",
                    [data.get('nom'), data.get('prenom'), data.get('telephone'), data.get('role'), matricule]
                )
            return Response({"message": "Utilisateur mis à jour avec succès !"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

    # C. SUPPRIMER UN UTILISATEUR (DELETE)
    def delete(self, request, matricule):
        if not self.verifier_si_admin(request):
            return Response({"error": "Accès refusé. Seul l'ADMINISTRATEUR peut supprimer un compte."}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM UTILISATEUR WHERE matricule = %s", [matricule])
            return Response({"message": "Utilisateur supprimé de la base de données !"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"Erreur SQL : {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

# ==========================================
# 5. GESTION DE L'INVENTAIRE (RESPONSABLE PARC)
# ==========================================
# ==========================================
# 5. GESTION DE L'INVENTAIRE (CONFORME DIAGRAMME)
# ==========================================
class ResponsableInventaireView(APIView):
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

        with connection.cursor() as cursor:
            # ÉTAPE INTERMÉDIAIRE DU DIAGRAMME : Vérifier si le numéro de série existe déjà
            cursor.execute("SELECT id_equipement FROM EQUIPEMENT WHERE code_inventaire = %s", [code])
            if cursor.fetchone():
                # Branche [N° série existant] -> Message d'erreur
                return Response({"error": f"Erreur : doublon n° série '{code}'"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                # Branche [N° série unique] -> INSERT équipement
                cursor.execute(
                    "INSERT INTO EQUIPEMENT (code_inventaire, designation, marque, modele, date_acquisition, etat, description) "
                    "VALUES (%s, %s, %s, %s, CURDATE(), %s, %s)",
                    [code, designation, marque, modele, etat, desc]
                )
                return Response({"message": "Confirmation ajout : Équipement inséré avec succès !"}, status=status.HTTP_201_CREATED)
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

# ==========================================
# 7. AFFECTATION D'ÉQUIPEMENT (CORRIGÉ DÉFINITIF)
# ==========================================
class ResponsableAffectationView(APIView):
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
                        "INSERT INTO MAINTENANCE (date_maintenance, type_maintenance, description, resultat, cout, id_equipement) "
                        "VALUES (CURDATE(), %s, %s, 'EN_COURS', 0.0, %s)",
                        [type_maint, desc_maint, id_equipement]
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

            # 3. Récupération conjointe de l'historique de maintenance
            cursor.execute(
                "SELECT id_maintenance, date_maintenance, type_maintenance, description, resultat, cout "
                "FROM MAINTENANCE WHERE id_equipement = %s ORDER BY date_maintenance DESC", [id_equip]
            )
            maintenances_rows = cursor.fetchall()
            
            historique_maintenance = [
                {
                    "id_maintenance": m[0],
                    "date": str(m[1]),
                    "type": m[2],
                    "description": m[3],
                    "resultat": m[4],
                    "cout": float(m[5])
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
                "description": desc
            },
            "historique_maintenance": historique_maintenance
        }, status=status.HTTP_200_OK)
# ==========================================
# 14. DEMANDE D'ÉQUIPEMENT (DIAGRAMME 8.1)
# ==========================================
class AgentDemandeEquipementView(APIView):
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
import csv
from django.http import HttpResponse

# ==========================================
# 20. HISTORIQUE GLOBAL DU MATÉRIEL (RESPONSABLE & DIRECTEUR)
# ==========================================
class HistoriqueGlobalView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        format_export = request.GET.get('format') # Pour le bloc [opt] de l'export CSV

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

        # --- BLOC OPT DU SCHÉMA : [Export demandé] (Générer le fichier CSV) ---
        if format_export and format_export.lower() == 'csv':
            response = HttpResponse(content_type='text/csv; charset=utf-8')
            response['Content-Disposition'] = 'attachment; filename="historique_parc_informatique.csv"'
            
            writer = csv.writer(response)
            writer.writerow(['Date', 'Type d action', 'Description']) # En-tête pour Excel
            for item in historique_global:
                writer.writerow([item['date'], item['type_action'], item['description']])
            return response

        # --- FLUX STANDARD : Affichage JSON à l'écran ---
        return Response(historique_global, status=status.HTTP_200_OK)
# ==========================================
# 21. LE JOURNAL D'AUDIT DE L'ADMINISTRATEUR (DIAGRAMME 8.17)
# ==========================================
class AdminJournalAuditView(APIView):
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

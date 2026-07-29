"""Adaptateur JWT pour les tables utilisateurs existantes du projet.

Les vues lisent principalement les claims ``matricule`` et ``role`` insérés
lors de la connexion. Cet adaptateur évite à DRF de rechercher automatiquement
un utilisateur Django dans une table différente de la table métier UTILISATEUR.
"""

from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import AnonymousUser

class DBeaverJWTAuthentication(JWTAuthentication):
    """Expose un utilisateur léger construit à partir des claims du JWT."""
    def get_user(self, validated_token):
        # Utilisateur non persisté : son identité vient uniquement du JWT validé.
        user = AnonymousUser()
        
        # Ces attributs sont utilisés par les vues pour appliquer les rôles.
        user.matricule = validated_token.get("matricule", "INCONNU")
        user.role = validated_token.get("role", "AGENT_BENEFICIAIRE")
        
        # DRF doit le considérer comme authentifié après validation du token.
        user.is_authenticated = True
        
        # Aucune requête automatique vers une table utilisateur Django n'est nécessaire.
        return user

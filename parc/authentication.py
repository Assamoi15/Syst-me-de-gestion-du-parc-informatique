from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import AnonymousUser

class DBeaverJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        # 1. On crée un utilisateur virtuel à la volée basé sur le contenu chiffré du Token
        user = AnonymousUser()
        
        # 2. On lui injecte directement son matricule et son rôle extraits du Token JWT
        user.matricule = validated_token.get("matricule", "INCONNU")
        user.role = validated_token.get("role", "AGENT_BENEFICIAIRE")
        
        # On force cet utilisateur virtuel à être considéré comme connecté par l'API
        user.is_authenticated = True
        
        # De cette façon, Django n'exécute AUCUNE requête SQL automatique sur sa table fictive
        return user

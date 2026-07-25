from rest_framework import serializers
from parc.models import Utilisateur

class UtilisateurSerializer(serializers.ModelSerializer):
    class Meta:
        model = Utilisateur
        fields = ['matricule', 'nom', 'prenom', 'mot_de_passe', 'telephone', 'role', 'is_active']
        extra_kwargs = {
            'mot_de_passe': {'write_only': True}  # Masque le mot de passe dans les réponses de l'API
        }

from django.db import connection
from django.utils import timezone

def enregistrer_audit(matricule_admin, action, description):
    """Insère une ligne dans la table HISTORIQUE pour tracer l'action"""
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO HISTORIQUE (date_action, action, description, utilisateur, id_equipement) "
            "VALUES (%s, %s, %s, %s, NULL)",
            [timezone.now().date(), action, description, matricule_admin]
        )

class EquipementSerializer(serializers.Serializer):
    id_equipement = serializers.IntegerField(read_only=True)
    code_inventaire = serializers.CharField(max_length=100)
    designation = serializers.CharField(max_length=255)
    marque = serializers.CharField(max_length=100, required=False, allow_blank=True)
    modele = serializers.CharField(max_length=100, required=False, allow_blank=True)
    date_acquisition = serializers.DateField(required=False, allow_null=True)
    etat = serializers.ChoiceField(
        choices=['DISPONIBLE', 'AFFECTE', 'EN_MAINTENANCE', 'HORS_SERVICE'],
        default='DISPONIBLE'
    )
    qr_code = serializers.CharField(max_length=255, required=False, allow_blank=True)
    description = serializers.CharField(required=False, allow_blank=True)



from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin


class UtilisateurManager(BaseUserManager):
    def create_user(self, matricule, nom, prenom, password=None, mot_de_passe=None, **extra_fields):
        if not matricule:
            raise ValueError("Le matricule est obligatoire.")

        if mot_de_passe is not None:
            password = mot_de_passe

        utilisateur = self.model(
            matricule=matricule,
            nom=nom,
            prenom=prenom,
            **extra_fields,
        )
        utilisateur.set_password(password)
        utilisateur.save(using=self._db)
        return utilisateur

    def create_superuser(self, matricule, nom, prenom, password=None, mot_de_passe=None, **extra_fields):
        extra_fields.setdefault("role", "ADMINISTRATEUR")
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        return self.create_user(matricule, nom, prenom, password, mot_de_passe=mot_de_passe, **extra_fields)


class Utilisateur(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ("AGENT_BENEFICIAIRE", "Agent Bénéficiaire"),
        ("RESPONSABLE_PARC", "Responsable Parc"),
        ("DIRECTEUR", "Directeur"),
        ("ADMINISTRATEUR", "Administrateur"),
    ]

    matricule = models.CharField(max_length=30, unique=True)
    nom = models.CharField(max_length=100)
    prenom = models.CharField(max_length=100)
    role = models.CharField(
        max_length=30,
        choices=ROLE_CHOICES,
        default="AGENT_BENEFICIAIRE",
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UtilisateurManager()

    USERNAME_FIELD = "matricule"
    REQUIRED_FIELDS = ["nom", "prenom"]

    def __str__(self):
        return f"{self.matricule} - {self.nom} {self.prenom}"
from django.contrib import admin
from django.urls import path
from parc.views import (
    LoginView, 
    AdminUserManagementView, 
    ResponsableInventaireView, 
    ResponsableAffectationView, 
    ResponsableDesaffectationView, 
    ResponsableTraiterDemandeView, 
    ResponsableDemandeAcquisitionView,
    ResponsableSuiviEquipementsView, 
    ResponsableMaintenanceView,
    EquipementFicheScanView, 
    AgentDemandeEquipementView,
    AgentSuiviDemandesView,
    AgentSignalerPanneView,
    AgentHistoriquePersonnelView,
    DirecteurAcquisitionView,
    DirecteurDashboardView,
    HistoriqueGlobalView,
    AdminJournalAuditView
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/login/', LoginView.as_view(), name='login'),
    
    # Routes Administrateur (Gestion des utilisateurs)
    path('api/admin/users/', AdminUserManagementView.as_view(), name='admin-users'),
    path('api/admin/users/<str:matricule>/', AdminUserManagementView.as_view(), name='admin-user-detail'),
    
    # ROUTE DU JOURNAL D'AUDIT DE L'ADMINISTRATEUR (DIAGRAMME 8.17)
    path('api/admin/audit-journal/', AdminJournalAuditView.as_view(), name='admin-audit-journal'),
    
    # Routes Responsable Parc
    path('api/parc/equipements/', ResponsableInventaireView.as_view(), name='parc-equipements'),
    path('api/parc/equipements/<int:id_equipement>/', ResponsableInventaireView.as_view(), name='parc-equipement-detail'),
    path('api/parc/affectations/', ResponsableAffectationView.as_view(), name='parc-affectations'),
    path('api/parc/desaffectations/', ResponsableDesaffectationView.as_view(), name='parc-desaffectations'),
    path('api/parc/demandes/traiter/', ResponsableTraiterDemandeView.as_view(), name='parc-traiter-demande'),
    path('api/parc/acquisitions/', ResponsableDemandeAcquisitionView.as_view(), name='parc-acquisitions'),
    path('api/parc/suivi/', ResponsableSuiviEquipementsView.as_view(), name='parc-suivi-global'),
    path('api/parc/suivi/<int:id_equipement>/', ResponsableSuiviEquipementsView.as_view(), name='parc-suivi-fiche'),
    path('api/parc/maintenances/', ResponsableMaintenanceView.as_view(), name='parc-maintenances'),
    path('api/parc/historique-global/', HistoriqueGlobalView.as_view(), name='historique-global'),
    
    # Routes Scan & QR Code Universel
    path('api/equipements/scan/', EquipementFicheScanView.as_view(), name='equipement-scan'),
    
    # Routes de l'Agent Bénéficiaire
    path('api/agent/demandes/', AgentDemandeEquipementView.as_view(), name='agent-creer-demande'),
    path('api/agent/demandes/suivi/', AgentSuiviDemandesView.as_view(), name='agent-suivi-demandes'),
    path('api/agent/demandes/suivi/<int:id_demande>/', AgentSuiviDemandesView.as_view(), name='agent-detail-demande'),
    path('api/agent/pannes/signaler/', AgentSignalerPanneView.as_view(), name='agent-signaler-panne'),
    path('api/agent/espace-personnel/', AgentHistoriquePersonnelView.as_view(), name='agent-espace-personnel'),
    
    # Routes du Directeur
    path('api/directeur/acquisitions/', DirecteurAcquisitionView.as_view(), name='directeur-acquisitions'),
    path('api/directeur/dashboard/', DirecteurDashboardView.as_view(), name='directeur-dashboard'),
]

-- Schéma métier du parc informatique.
--
-- Ce schéma n'a jamais existé sous forme de migration Django ou de script
-- SQL versionné : le code de parc/views.py fait du SQL brut sur des tables
-- supposées déjà exister (créées à la main, ex. via DBeaver, en développement
-- local). Il a été reconstitué en listant chaque colonne réellement utilisée
-- dans les requêtes SELECT/INSERT/UPDATE de parc/views.py. À exécuter une
-- seule fois sur une base vide, après avoir créé la base elle-même :
--
--   mysql -u root -p parc < deploy/schema.sql
--
-- Ne touche pas aux tables gérées par les migrations Django
-- (django_migrations, auth_*, parc_utilisateur, etc.) : elles restent en
-- place, ce script ne crée que les 8 tables métier interrogées en SQL brut.

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

CREATE TABLE IF NOT EXISTS UTILISATEUR (
    matricule       VARCHAR(30)  NOT NULL PRIMARY KEY,
    nom             VARCHAR(100) NOT NULL,
    prenom          VARCHAR(100) NOT NULL,
    mot_de_passe    VARCHAR(255) NOT NULL,
    telephone       VARCHAR(30)  NOT NULL DEFAULT '',
    date_creation   DATE         NOT NULL,
    role            VARCHAR(30)  NOT NULL DEFAULT 'AGENT_BENEFICIAIRE',
    is_active       TINYINT(1)   NOT NULL DEFAULT 1,
    last_login      DATETIME     NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS EQUIPEMENT (
    id_equipement    INT AUTO_INCREMENT PRIMARY KEY,
    code_inventaire  VARCHAR(100) NOT NULL UNIQUE,
    designation      VARCHAR(150) NOT NULL,
    marque           VARCHAR(100) NOT NULL DEFAULT '',
    modele           VARCHAR(100) NOT NULL DEFAULT '',
    date_acquisition DATE         NOT NULL,
    etat             VARCHAR(30)  NOT NULL DEFAULT 'DISPONIBLE',
    description      TEXT         NULL,
    qr_code          VARCHAR(150) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS AFFECTATION (
    id_affectation       INT AUTO_INCREMENT PRIMARY KEY,
    date_affectation     DATE        NOT NULL,
    date_restitution     DATE        NULL,
    statut               VARCHAR(30) NOT NULL DEFAULT 'EN_COURS',
    matricule_agent      VARCHAR(30) NOT NULL,
    id_equipement        INT         NOT NULL,
    matricule_responsable VARCHAR(30) NULL,
    CONSTRAINT fk_affectation_agent FOREIGN KEY (matricule_agent) REFERENCES UTILISATEUR(matricule),
    CONSTRAINT fk_affectation_equipement FOREIGN KEY (id_equipement) REFERENCES EQUIPEMENT(id_equipement),
    CONSTRAINT fk_affectation_responsable FOREIGN KEY (matricule_responsable) REFERENCES UTILISATEUR(matricule)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS DEMANDE_EQUIPEMENT (
    id_demande            INT AUTO_INCREMENT PRIMARY KEY,
    date_demande          DATE        NOT NULL,
    motif                 TEXT        NULL,
    statut                VARCHAR(30) NOT NULL DEFAULT 'EN_ATTENTE',
    designation_materiel  VARCHAR(150) NOT NULL,
    matricule_agent       VARCHAR(30) NOT NULL,
    matricule_responsable VARCHAR(30) NULL,
    CONSTRAINT fk_demande_equip_agent FOREIGN KEY (matricule_agent) REFERENCES UTILISATEUR(matricule),
    CONSTRAINT fk_demande_equip_responsable FOREIGN KEY (matricule_responsable) REFERENCES UTILISATEUR(matricule)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS DEMANDE_ACQUISITION (
    id_acquisition        INT AUTO_INCREMENT PRIMARY KEY,
    date_demande          DATE        NOT NULL,
    motif                 TEXT        NULL,
    statut                VARCHAR(30) NOT NULL DEFAULT 'EN_ATTENTE',
    designation_materiel  VARCHAR(150) NOT NULL,
    id_demande_equipement INT         NULL,
    matricule_directeur   VARCHAR(30) NULL,
    matricule_admin       VARCHAR(30) NULL,
    CONSTRAINT fk_acquisition_demande FOREIGN KEY (id_demande_equipement) REFERENCES DEMANDE_EQUIPEMENT(id_demande),
    CONSTRAINT fk_acquisition_directeur FOREIGN KEY (matricule_directeur) REFERENCES UTILISATEUR(matricule),
    CONSTRAINT fk_acquisition_admin FOREIGN KEY (matricule_admin) REFERENCES UTILISATEUR(matricule)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS MAINTENANCE (
    id_maintenance        INT AUTO_INCREMENT PRIMARY KEY,
    date_maintenance      DATE        NOT NULL,
    type_maintenance      VARCHAR(30) NOT NULL DEFAULT 'CORRECTIVE',
    description           TEXT        NULL,
    resultat              VARCHAR(100) NOT NULL DEFAULT 'EN_COURS',
    cout                  DECIMAL(10,2) NOT NULL DEFAULT 0.00,
    id_equipement         INT         NOT NULL,
    matricule_intervenant VARCHAR(30) NULL,
    CONSTRAINT fk_maintenance_equipement FOREIGN KEY (id_equipement) REFERENCES EQUIPEMENT(id_equipement),
    CONSTRAINT fk_maintenance_intervenant FOREIGN KEY (matricule_intervenant) REFERENCES UTILISATEUR(matricule)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS PANNE (
    id_panne        INT AUTO_INCREMENT PRIMARY KEY,
    date_panne      DATE        NOT NULL,
    description     TEXT        NULL,
    statut          VARCHAR(30) NOT NULL DEFAULT 'OUVERTE',
    id_equipement   INT         NOT NULL,
    matricule_agent VARCHAR(30) NULL,
    id_maintenance  INT         NULL,
    CONSTRAINT fk_panne_equipement FOREIGN KEY (id_equipement) REFERENCES EQUIPEMENT(id_equipement),
    CONSTRAINT fk_panne_agent FOREIGN KEY (matricule_agent) REFERENCES UTILISATEUR(matricule),
    CONSTRAINT fk_panne_maintenance FOREIGN KEY (id_maintenance) REFERENCES MAINTENANCE(id_maintenance)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS HISTORIQUE (
    id_historique  INT AUTO_INCREMENT PRIMARY KEY,
    date_action    DATE        NOT NULL,
    action         VARCHAR(100) NOT NULL,
    description    TEXT        NULL,
    utilisateur    VARCHAR(30) NULL,
    id_equipement  INT         NULL,
    CONSTRAINT fk_historique_utilisateur FOREIGN KEY (utilisateur) REFERENCES UTILISATEUR(matricule),
    CONSTRAINT fk_historique_equipement FOREIGN KEY (id_equipement) REFERENCES EQUIPEMENT(id_equipement)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;

-- Compte administrateur de démarrage (mot de passe en clair : il sera
-- automatiquement hashé au premier login réussi par LoginView). À changer
-- immédiatement après connexion via PATCH /api/admin/users/<matricule>/.
INSERT INTO UTILISATEUR (matricule, nom, prenom, mot_de_passe, telephone, date_creation, role, is_active)
SELECT 'ADM-2026-001', 'Admin', 'Systeme', 'ChangeMoiImmediatement2026!', '', CURDATE(), 'ADMINISTRATEUR', 1
WHERE NOT EXISTS (SELECT 1 FROM UTILISATEUR WHERE matricule = 'ADM-2026-001');

# Event Manager Application

## Description
Un gestionnaire d'événements complet avec des fonctionnalités d'authentification, de gestion d'événements et d'administration.

## Fonctionnalités
- Inscription et authentification des utilisateurs
- Création et gestion d'événements
- Interface d'administration
- Super admin pour la gestion des administrateurs

## Prérequis
- Python 3.8+
- pip
- virtualenv (recommandé)

## Installation

1. Clonez le dépôt
```bash
git clone https://github.com/votre_username/event_manager.git
cd event_manager
```

2. Créez et activez un environnement virtuel
```bash
python -m venv venv
# Sur Windows
venv\Scripts\activate
# Sur macOS/Linux
source venv/bin/activate
```

3. Installez les dépendances
```bash
pip install -r requirements.txt
```

4. Initialisez la base de données
```bash
python create_sample_data.py
```

5. Lancez l'application
```bash
python app.py
```

## Comptes par défaut
- Super Admin
  - Nom d'utilisateur: `pogoparis`
  - Mot de passe: `SuperAdmin2024!`

- Admin
  - Nom d'utilisateur: `admin`
  - Mot de passe: `admin123`

## Technologies Utilisées
- Flask
- SQLAlchemy
- Flask-Login
- Bootstrap 5
- SQLite

## Licence
MIT License

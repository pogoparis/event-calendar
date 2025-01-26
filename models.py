# Importations des bibliothèques nécessaires pour la gestion des modèles de données
from flask_login import UserMixin
from datetime import datetime
from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
import os

class User(UserMixin, db.Model):
    """
    Modèle représentant un utilisateur dans le système.
    
    Hérite de UserMixin pour une intégration facile avec Flask-Login
    et de db.Model pour la persistance des données avec SQLAlchemy.
    
    Attributs:
    - id: Identifiant unique de l'utilisateur
    - username: Nom d'utilisateur unique
    - email: Adresse email unique
    - password_hash: Mot de passe haché pour la sécurité
    - first_name: Prénom de l'utilisateur (optionnel)
    - last_name: Nom de famille de l'utilisateur (optionnel)
    - phone: Numéro de téléphone de l'utilisateur (optionnel)
    - is_admin: Indique si l'utilisateur est un administrateur
    - is_super_admin: Indique si l'utilisateur est un super administrateur
    - registrations: Liste des inscriptions de l'utilisateur aux événements
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(80), nullable=True)
    last_name = db.Column(db.String(80), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    registrations = db.relationship('Registration', backref='user', lazy=True)

    def set_password(self, password):
        """
        Définit le mot de passe de l'utilisateur en le hachant.
        
        :param password: Mot de passe en texte brut
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Vérifie si le mot de passe fourni correspond au mot de passe haché.
        
        :param password: Mot de passe à vérifier
        :return: True si le mot de passe est correct, False sinon
        """
        return check_password_hash(self.password_hash, password)

class Event(db.Model):
    """
    Modèle représentant un événement dans le système.
    
    Attributs:
    - id: Identifiant unique de l'événement
    - title: Titre de l'événement
    - description: Description détaillée de l'événement
    - date: Date et heure de l'événement
    - location: Lieu de l'événement
    - organizer: Organisateur de l'événement
    - capacity: Nombre maximum de participants
    - price: Prix de l'événement
    - additional_info: Informations supplémentaires
    - address: Adresse complète de l'événement
    - is_active: Statut actif/inactif de l'événement
    - image_url: URL de l'image de l'événement
    - registrations: Liste des inscriptions à l'événement
    """
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=True)
    organizer = db.Column(db.String(100), nullable=True)
    capacity = db.Column(db.Integer, nullable=True)
    price = db.Column(db.Float, nullable=True)
    additional_info = db.Column(db.Text, nullable=True)
    address = db.Column(db.String(300), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    image_url = db.Column(db.String(300), nullable=True)
    registrations = db.relationship('Registration', backref='event', lazy='dynamic')

    def is_past_event(self):
        """
        Détermine si l'événement est un événement passé.
        
        Compare la date de l'événement avec la date et l'heure actuelles.
        
        :return: True si l'événement est passé, False sinon
        """
        # Utiliser datetime.now() avec timezone aware si possible
        current_time = datetime.now()
        
        # Comparaison explicite et détaillée
        is_past = False
        
        # Comparer année
        if self.date.year < current_time.year:
            is_past = True
        # Si même année, comparer mois
        elif self.date.year == current_time.year and self.date.month < current_time.month:
            is_past = True
        # Si même année et même mois, comparer jour
        elif (self.date.year == current_time.year and 
              self.date.month == current_time.month and 
              self.date.day < current_time.day):
            is_past = True
        # Si même année, même mois, même jour, comparer heure
        elif (self.date.year == current_time.year and 
              self.date.month == current_time.month and 
              self.date.day == current_time.day and 
              self.date.hour < current_time.hour):
            is_past = True
        # Si même année, même mois, même jour, même heure, comparer minute
        elif (self.date.year == current_time.year and 
              self.date.month == current_time.month and 
              self.date.day == current_time.day and 
              self.date.hour == current_time.hour and 
              self.date.minute < current_time.minute):
            is_past = True
        
        return is_past

    def update_active_status(self):
        """
        Met à jour le statut actif de l'événement en fonction de sa date.
        
        Définit is_active à False si l'événement est passé.
        """
        self.is_active = not self.is_past_event()

    def is_registration_possible(self):
        """
        Vérifie si l'inscription à l'événement est possible.
        
        :return: True si l'événement n'est pas passé et a des places disponibles, False sinon
        """
        return (not self.is_past_event() and 
                (self.capacity is None or self.get_remaining_spots() > 0))

    def get_registration_count(self):
        """
        Compte le nombre d'inscriptions à l'événement.
        
        :return: Nombre total d'inscriptions
        """
        return self.registrations.count()

    def get_remaining_spots(self):
        """
        Calcule le nombre de places restantes.
        
        :return: Nombre de places restantes ou infini si pas de limite
        """
        return self.capacity - self.get_registration_count() if self.capacity else float('inf')

    def get_event_image(self):
        """
        Retourne le chemin de l'image de l'événement.
        Si aucune image n'est définie, retourne une image par défaut.
        """
        # Vérifier si image_url est définie et non vide
        if self.image_url:
            # Chemins de base
            base_paths = [
                'static',
                'C:/Users/Administrateur/CascadeProjects/event_manager/static'
            ]
            
            # Extraire le nom de fichier
            filename = os.path.basename(self.image_url.replace('/static/uploads/events/', ''))
            
            # Liste des chemins possibles à vérifier
            possible_paths = []
            for base_path in base_paths:
                possible_paths.extend([
                    os.path.join(base_path, 'uploads', 'events', filename),
                    os.path.join(base_path, 'uploads', 'events', os.path.basename(filename)),
                    os.path.join(base_path, self.image_url.replace('/static/', ''))
                ])
            
            # Vérifier chaque chemin possible
            for path in possible_paths:
                if os.path.exists(path):
                    # Retourner le chemin exact comme stocké dans la base de données
                    return self.image_url.replace('/static/', '')
        
        # Dictionnaire de mapping des catégories d'événements
        event_categories = {
            'Conférence': 'conference.jpg',
            'Festival': 'festival.jpg',
            'Salon': 'salon.jpg',
            'Marathon': 'marathon.jpg',
            'Atelier': 'atelier.jpg'
        }
        
        # Trouver la catégorie correspondante
        for category, default_image in event_categories.items():
            if category.lower() in self.title.lower():
                return f'images/default/{default_image}'
        
        # Image générique par défaut si aucune correspondance
        return 'images/default/event.jpg'

class Registration(db.Model):
    """
    Modèle représentant une inscription à un événement.
    
    Attributs:
    - id: Identifiant unique de l'inscription
    - user_id: Identifiant de l'utilisateur inscrit
    - event_id: Identifiant de l'événement
    - registration_date: Date et heure de l'inscription
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)

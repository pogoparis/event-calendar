from flask_login import UserMixin
from datetime import datetime
from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(80), nullable=True)
    last_name = db.Column(db.String(80), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
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
        # Débogage complet avec informations détaillées
        import traceback
        
        current_time = datetime.now()
        
        # Logs détaillés
        print("\n--- DÉBOGAGE ÉVÉNEMENT ---")
        print(f"Titre de l'événement : {self.title}")
        print(f"Date de l'événement : {self.date}")
        print(f"Date actuelle : {current_time}")
        print(f"Année de l'événement : {self.date.year}")
        print(f"Année actuelle : {current_time.year}")
        
        # Comparaison année par année
        is_past = (
            self.date.year < current_time.year or 
            (self.date.year == current_time.year and 
             (self.date.month < current_time.month or 
              (self.date.month == current_time.month and 
               self.date.day < current_time.day)))
        )
        
        print(f"Est-ce un événement passé ? {is_past}")
        print("Trace de la pile :")
        traceback.print_stack()
        print("--- FIN DÉBOGAGE ---\n")
        
        return is_past

    def update_active_status(self):
        self.is_active = not self.is_past_event()

    def is_registration_possible(self):
        return (not self.is_past_event() and 
                (self.capacity is None or self.get_remaining_spots() > 0))

    def get_registration_count(self):
        return self.registrations.count()

    def get_remaining_spots(self):
        return self.capacity - self.get_registration_count() if self.capacity else float('inf')

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)

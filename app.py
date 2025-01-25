from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateTimeField, FloatField, IntegerField, HiddenField, SelectField
from wtforms.validators import DataRequired, Email, Length, ValidationError, Regexp, Optional, URL, NumberRange
import re
import logging
import sys
from flask_wtf import FlaskForm

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['GOOGLE_MAPS_API_KEY'] = 'AIzaSyBgr-XvksV_FShQH-I99HySlKRlSvc2pAM'  # Placez votre clé API Google Maps ici
app.config['WTF_CSRF_ENABLED'] = True
app.config['DEBUG'] = True
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configuration du logging
import logging
import sys

# Créer un logger personnalisé
logger = logging.getLogger('event_manager')
logger.setLevel(logging.DEBUG)

# Créer un gestionnaire de console
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)

# Créer un formateur
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

# Ajouter le gestionnaire au logger
logger.addHandler(console_handler)

# Désactiver la propagation pour éviter les doublons
logger.propagate = False

# Configuration du login_manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.unauthorized_handler
def unauthorized():
    """
    Gère les accès non autorisés.
    
    Returns:
        Redirection vers la page de connexion avec un message
    """
    flash('Veuillez vous connecter pour accéder à cette page.', 'info')
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Constantes pour les messages d'erreur
ERROR_MESSAGES = {
    'title_required': 'Le titre est obligatoire',
    'description_required': 'La description est obligatoire',
    'date_required': 'La date est obligatoire',
    'date_format': 'Format de date invalide. Utilisez JJ/MM/AAAA (exemple : 25/01/2025)',
    'date_past': 'La date de l\'événement doit être dans le futur ou aujourd\'hui.',
    'date_invalid': 'Date invalide. Vérifiez que la date existe réellement.',
    'time_format': 'Format d\'heure invalide. Utilisez HH:MM',
    'location_required': 'Le lieu est obligatoire',
    'capacity_positive': 'La capacité doit être un nombre strictement positif',
    'price_non_negative': 'Le prix doit être un nombre non négatif'
}

def validate_phone(form, field):
    """
    Valide un numéro de téléphone français.
    
    Formats acceptés : 
    - +33 6 12 34 56 78
    - 0612345678
    - 06 12 34 56 78
    
    Args:
        form: Le formulaire en cours de validation
        field: Le champ de téléphone à valider
    
    Raises:
        ValidationError: Si le numéro de téléphone ne correspond pas au format attendu
    """
    phone_regex = r'^(\+33|0)[1-9](\s?[0-9]{2}){4}$'
    if field.data and not re.match(phone_regex, field.data):
        raise ValidationError('Numéro de téléphone invalide. Format attendu : 0612345678 ou +33 6 12 34 56 78')

def validate_date(form, field):
    """
    Valide que la date est au format JJ/MM/AAAA et dans le futur.
    
    Args:
        form: Le formulaire en cours de validation
        field: Le champ de date à valider
    
    Raises:
        ValidationError: Si la date ne respecte pas les critères de validation
    """
    if field.data:
        # Supprimer les espaces avant et après
        date_str = field.data.strip()
        
        # Vérifier le format exact
        if not re.match(r'^\d{2}/\d{2}/\d{4}$', date_str):
            raise ValidationError(ERROR_MESSAGES['date_format'])
        
        try:
            # Validation du format JJ/MM/AAAA
            parsed_date = datetime.strptime(date_str, '%d/%m/%Y').date()
            
            # Vérifier que la date n'est pas dans le passé
            if parsed_date < datetime.now().date():
                raise ValidationError(ERROR_MESSAGES['date_past'])
        
        except ValueError:
            raise ValidationError(ERROR_MESSAGES['date_invalid'])

def validate_time(form, field):
    """
    Valide le format de l'heure.
    
    Args:
        form: Le formulaire en cours de validation
        field: Le champ de temps à valider
    
    Raises:
        ValidationError: Si l'heure ne respecte pas le format HH:MM
    """
    if field.data:
        # Expression régulière pour forcer HH:MM avec un zéro devant
        time_regex = r'^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$'
        
        if not re.match(time_regex, field.data):
            raise ValidationError(ERROR_MESSAGES['time_format'])

def validate_capacity(form, field):
    """
    Valide la capacité de l'événement.
    
    Args:
        form: Le formulaire en cours de validation
        field: Le champ de capacité à valider
    
    Raises:
        ValidationError: Si la capacité n'est pas un nombre strictement positif
    """
    # Vérifier si le champ est rempli (Optional() le laisse passer)
    if field.data is not None:
        # Vérifier explicitement que la valeur est strictement positive
        try:
            # Convertir en entier pour être sûr
            value = int(field.data)
            
            # Vérifier que la valeur est strictement positive
            if value <= 0:
                raise ValidationError(ERROR_MESSAGES['capacity_positive'])
        except (ValueError, TypeError):
            # Si la conversion échoue, c'est que la valeur n'est pas un nombre
            raise ValidationError(ERROR_MESSAGES['capacity_positive'])

def validate_price(form, field):
    """
    Valide le prix de l'événement.
    
    Args:
        form: Le formulaire en cours de validation
        field: Le champ de prix à valider
    
    Raises:
        ValidationError: Si le prix est négatif
    """
    # Vérifier si le champ est rempli (Optional() le laisse passer)
    if field.data is not None:
        try:
            # Convertir en float pour être sûr
            value = float(field.data)
            
            # Vérifier que le prix n'est pas négatif
            if value < 0:
                raise ValidationError(ERROR_MESSAGES['price_non_negative'])
        except (ValueError, TypeError):
            # Si la conversion échoue, c'est que la valeur n'est pas un nombre
            raise ValidationError(ERROR_MESSAGES['price_non_negative'])

def validate_image_url(form, field):
    """
    Valide l'URL de l'image si elle est fournie.
    
    Args:
        form: Le formulaire en cours de validation
        field: Le champ d'URL de l'image à valider
    
    Raises:
        ValidationError: Si l'URL n'est pas valide
    """
    if field.data:
        url_validator = URL(message="L'URL de l'image n'est pas valide. Veuillez entrer une URL complète.")
        url_validator(form, field)

def validate_email(form, field):
    """
    Validation détaillée de l'email
    """
    print(f"DEBUG: Validating email '{field.data}'")
    
    email = field.data
    
    # Vérification de base
    if not email:
        print("DEBUG: Email is empty")
        raise ValidationError('Email obligatoire')
    
    # Vérification de la présence de @
    if '@' not in email:
        print(f"DEBUG: Email '{email}' does not contain @")
        raise ValidationError('L\'email doit contenir le symbole @')
    
    # Séparation du nom et du domaine
    try:
        username, domain = email.split('@')
    except ValueError:
        raise ValidationError('Format d\'email invalide')
    
    # Vérification que le nom et le domaine ne sont pas vides
    if not username or not domain:
        raise ValidationError('Veuillez saisir un email complet')
    
    # Vérification du format de base avec regex
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        raise ValidationError('Format d\'email invalide')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(80), nullable=True)
    last_name = db.Column(db.String(80), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    registrations = db.relationship('Registration', backref='user', lazy=True)
    
    def validate_phone(self):
        """
        Valide un numéro de téléphone français
        Formats acceptés : 
        - +33 6 12 34 56 78
        - 0612345678
        - 06 12 34 56 78
        
        Args:
            form: Le formulaire en cours de validation
            field: Le champ de téléphone à valider
        
        Raises:
            ValidationError: Si le numéro de téléphone ne correspond pas au format attendu
        """
        if self.phone:
            phone_regex = r'^(\+33|0)[1-9](\s?[0-9]{2}){4}$'
            return bool(re.match(phone_regex, self.phone))
        return True  # Téléphone facultatif

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
    registrations = db.relationship('Registration', backref='event', lazy='dynamic')
    image_url = db.Column(db.String(500), nullable=True)  # Nouveau champ pour l'URL de l'image

    @property
    def is_past_event(self):
        """
        Vérifie si l'événement est passé.
        
        Returns:
            bool: True si l'événement est passé, False sinon
        """
        return self.date.date() < datetime.now().date()

    def update_active_status(self):
        """
        Met à jour le statut actif de l'événement en fonction de sa date.
        """
        self.is_active = not self.is_past_event
        db.session.commit()

    def is_registration_possible(self):
        """
        Vérifie si l'inscription est possible en fonction de la capacité.
        
        Returns:
            bool: True si l'inscription est possible, False sinon
        """
        if self.capacity is None:
            return True
        
        current_registrations = self.registrations.count()
        return current_registrations < self.capacity

    def get_remaining_spots(self):
        """
        Calcule le nombre de places restantes.
        
        Returns:
            int: Nombre de places restantes, ou None si pas de limite
        """
        if self.capacity is None:
            return None
        
        current_registrations = self.registrations.count()
        return max(0, self.capacity - current_registrations)

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)

class ProfileForm(FlaskForm):
    """
    Formulaire de profil utilisateur avec validation de téléphone optionnelle.
    """
    username = StringField('Nom d\'utilisateur', render_kw={'readonly': True})
    first_name = StringField('Prénom')
    last_name = StringField('Nom')
    phone = StringField('Téléphone', validators=[validate_phone])
    new_password = PasswordField('Nouveau mot de passe')
    submit = SubmitField('Mettre à jour')

class CreateEventForm(FlaskForm):
    """
    Formulaire de création et modification d'événement avec validations complètes.
    
    Inclut des validations pour :
    - Champs obligatoires
    - Format de date
    - Plage de valeurs pour capacité et prix
    """
    title = StringField('Titre', validators=[
        DataRequired(message=ERROR_MESSAGES['title_required'])
    ])
    description = TextAreaField('Description', validators=[
        DataRequired(message=ERROR_MESSAGES['description_required'])
    ])
    
    # Champs de date et heure avec validation
    event_date = StringField('Date', validators=[
        DataRequired(message=ERROR_MESSAGES['date_required']),
        validate_date
    ])
    event_time = StringField('Heure', validators=[
        DataRequired(message=ERROR_MESSAGES['time_format']),
        validate_time
    ])
    
    # Champs avec validation moins stricte
    location = StringField('Lieu', validators=[
        DataRequired(message=ERROR_MESSAGES['location_required'])
    ])
    address = StringField('Adresse')
    organizer = StringField('Organisateur')
    
    # Champs numériques optionnels avec validation
    capacity = IntegerField('Capacité', validators=[
        Optional(), 
        validate_capacity
    ])
    price = FloatField('Prix', validators=[
        Optional(), 
        validate_price
    ])
    
    additional_info = TextAreaField('Informations supplémentaires')
    image_url = StringField('URL de l\'image', validators=[Optional(), validate_image_url])  # Nouveau champ pour l'URL de l'image
    submit = SubmitField('Créer l\'événement')

    def validate(self, extra_validators=None):
        """
        Surcharge de la méthode de validation pour forcer une validation stricte des champs optionnels
        """
        # Validation standard
        result = super().validate(extra_validators)
        
        # Validation supplémentaire pour les champs optionnels
        if result:
            # Vérification stricte de la capacité
            if self.capacity.data is not None:
                try:
                    value = int(self.capacity.data)
                    if value <= 0:
                        self.capacity.errors.append(ERROR_MESSAGES['capacity_positive'])
                        result = False
                except (ValueError, TypeError):
                    self.capacity.errors.append(ERROR_MESSAGES['capacity_positive'])
                    result = False
            
            # Vérification stricte du prix
            if self.price.data is not None:
                try:
                    value = float(self.price.data)
                    if value < 0:
                        self.price.errors.append(ERROR_MESSAGES['price_non_negative'])
                        result = False
                except (ValueError, TypeError):
                    self.price.errors.append(ERROR_MESSAGES['price_non_negative'])
                    result = False
        
        return result

# Utiliser le même formulaire pour la modification
EventForm = CreateEventForm

class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Connexion')

class RegisterForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[
        DataRequired(message='Nom d\'utilisateur obligatoire')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email obligatoire'),
        validate_email
    ])
    password = PasswordField('Mot de passe', validators=[
        DataRequired(message='Mot de passe obligatoire')
    ])
    submit = SubmitField('S\'inscrire')

    def validate(self, extra_validators=None):
        """
        Surcharge de la méthode de validation pour forcer une validation stricte
        """
        # Validation de base
        if not super().validate(extra_validators):
            return False
        
        # Validation supplémentaire
        if not self.username.data or len(self.username.data.strip()) == 0:
            self.username.errors.append('Nom d\'utilisateur obligatoire')
            return False
        
        if not self.email.data or len(self.email.data.strip()) == 0:
            self.email.errors.append('Email obligatoire')
            return False
        
        if not self.password.data or len(self.password.data.strip()) == 0:
            self.password.errors.append('Mot de passe obligatoire')
            return False
        
        return True

class UnregisterEventForm(FlaskForm):
    submit = SubmitField('Se désinscrire')

class ArchiveEventForm(FlaskForm):
    submit = SubmitField('Archiver/Désarchiver')

class SuperAdminForm(FlaskForm):
    """
    Formulaire pour les actions du super admin
    """
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), validate_email])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    action = SelectField('Action', choices=[
        ('create_user', 'Créer un utilisateur'), 
        ('create_admin', 'Créer un administrateur')
    ], validators=[DataRequired()])
    submit = SubmitField('Exécuter', render_kw={'id': 'super_admin_submit'})

class DeleteUserForm(FlaskForm):
    """
    Formulaire pour supprimer un utilisateur
    """
    user_id = HiddenField('ID Utilisateur', validators=[DataRequired()])
    submit = SubmitField('Supprimer', render_kw={'id': 'delete_user_submit'})

def get_events(show_past=False):
    """
    Récupère les événements, avec option pour afficher/masquer les événements passés.
    
    Args:
        show_past (bool): Si True, affiche tous les événements actifs. 
                           Si False, n'affiche que les événements à venir.
    
    Returns:
        list: Liste des événements filtrés
    """
    if show_past:
        # Récupère tous les événements actifs, triés par date décroissante
        return Event.query.filter(Event.is_active == True).order_by(Event.date.desc()).all()
    else:
        # Récupère uniquement les événements futurs et actifs
        return Event.query.filter(
            Event.date >= datetime.now(), 
            Event.is_active == True
        ).order_by(Event.date).all()

@app.route('/')
def index():
    """
    Page d'accueil affichant les événements.
    
    Returns:
        Rendu du template index avec les événements
    """
    # Récupérer tous les événements
    events = Event.query.order_by(Event.date).all()
    
    # Initialiser les variables
    user_registrations = []
    form = None
    
    # Si l'utilisateur est connecté, récupérer ses inscriptions
    if current_user.is_authenticated:
        user_registrations = [reg.event_id for reg in current_user.registrations]
        
        # Créer un formulaire de désinscription pour chaque événement inscrit
        form = UnregisterEventForm()
    
    return render_template('index.html', 
                           events=events, 
                           user_registrations=user_registrations,
                           form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Gère la connexion des utilisateurs.
    
    Returns:
        Redirection vers la page appropriée ou rendu du formulaire de connexion
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Connexion réussie !', 'success')
            return redirect(url_for('index'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if request.method == 'POST':
        # Vérifications minimales
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
        # Vérifier si les champs sont remplis
        if not (username and email and password):
            flash('Tous les champs sont obligatoires', 'danger')
            return render_template('register.html', form=form)
        
        # Vérifier si le nom d'utilisateur existe déjà
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Ce nom d\'utilisateur est déjà utilisé', 'danger')
            return render_template('register.html', form=form)
        
        # Vérifier si l'email existe déjà
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Cet email est déjà utilisé', 'danger')
            return render_template('register.html', form=form)
        
        # Créer l'utilisateur
        new_user = User(
            username=username, 
            email=email, 
            password_hash=generate_password_hash(password)
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Connecter l'utilisateur automatiquement
            login_user(new_user)
            
            flash('Inscription réussie !', 'success')
            return redirect(url_for('index'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Erreur lors de l\'inscription : {str(e)}', 'danger')
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """
    Déconnecte l'utilisateur actuel.
    
    Returns:
        Redirection vers la page d'accueil
    """
    logout_user()
    flash('Vous avez été déconnecté avec succès.', 'success')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    # Show only non-admin users
    users = User.query.filter_by(is_admin=False).all()
    events = Event.query.all()
    return render_template('admin.html', users=users, events=events)

@app.route('/admin/event/create', methods=['GET', 'POST'])
@login_required
def create_event():
    # Vérifier que l'utilisateur est admin
    if not current_user.is_admin:
        flash('Vous n\'avez pas les droits pour créer un événement', 'danger')
        return redirect(url_for('index'))
    
    # Créer le formulaire
    form = CreateEventForm()
    
    if form.validate_on_submit():
        try:
            # Convertir la date et l'heure
            event_datetime = datetime.strptime(f"{form.event_date.data} {form.event_time.data}", '%d/%m/%Y %H:%M')
            
            # Créer un nouvel événement
            new_event = Event(
                title=form.title.data,
                description=form.description.data,
                date=event_datetime,
                location=form.location.data,
                address=form.address.data,
                organizer=form.organizer.data,
                capacity=form.capacity.data,
                price=form.price.data,
                additional_info=form.additional_info.data,
                image_url=form.image_url.data  # Nouveau champ pour l'URL de l'image
            )
            
            # Ajouter et enregistrer l'événement
            db.session.add(new_event)
            db.session.commit()
            
            flash('Événement créé avec succès', 'success')
            return redirect(url_for('event_detail', event_id=new_event.id))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Erreur lors de la création de l\'événement : {str(e)}', 'danger')
    
    return render_template('create_event.html', form=form)

@app.route('/admin/edit_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    # Vérifier que l'utilisateur est admin
    if not current_user.is_admin:
        flash('Vous n\'avez pas les droits pour modifier cet événement', 'danger')
        return redirect(url_for('index'))
    
    # Récupérer l'événement
    event = Event.query.get_or_404(event_id)
    
    # Créer le formulaire
    form = EventForm(obj=event)
    
    if form.validate_on_submit():
        try:
            # Mettre à jour tous les champs de l'événement
            form.populate_obj(event)
            
            # Convertir la date si nécessaire
            if form.event_date.data and form.event_time.data:
                event.date = datetime.strptime(f"{form.event_date.data} {form.event_time.data}", '%d/%m/%Y %H:%M')
            
            db.session.commit()
            flash('Événement modifié avec succès', 'success')
            return redirect(url_for('event_detail', event_id=event_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Erreur lors de la modification : {str(e)}', 'danger')
    
    return render_template('edit_event.html', form=form, event=event)

@app.route('/super_admin', methods=['GET', 'POST'])
@login_required
def super_admin():
    # Only allow access to super admin (currently only 'pogoparis')
    if not current_user.is_admin or current_user.username != 'pogoparis':
        flash('Vous n\'avez pas les autorisations requises.', 'danger')
        return redirect(url_for('index'))
    
    form = SuperAdminForm()
    delete_user_form = DeleteUserForm()
    
    if form.validate_on_submit():
        # Logique de création d'utilisateur (inchangée)
        existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if existing_user:
            flash('Un utilisateur avec ce nom ou email existe déjà.', 'danger')
        else:
            new_user = User(
                username=form.username.data, 
                email=form.email.data, 
                password_hash=generate_password_hash(form.password.data),
                is_admin=form.action.data == 'create_admin'
            )
            db.session.add(new_user)
            try:
                db.session.commit()
                flash(f'Nouvel {"administrateur" if form.action.data == "create_admin" else "utilisateur"} créé avec succès.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Erreur lors de la création : {str(e)}', 'danger')
    
    # Gestion de la suppression d'utilisateur
    if delete_user_form.validate_on_submit():
        user_id = delete_user_form.user_id.data
        user = User.query.get(user_id)
        
        if user and user.username != 'pogoparis':
            try:
                # Supprimer d'abord les inscriptions associées
                Registration.query.filter_by(user_id=user.id).delete()
                
                # Puis supprimer l'utilisateur
                db.session.delete(user)
                db.session.commit()
                flash('Utilisateur supprimé avec succès.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Erreur lors de la suppression de l\'utilisateur: {str(e)}', 'danger')
        else:
            flash('Impossible de supprimer cet utilisateur.', 'danger')
    
    # Get all admin users
    admins = User.query.filter_by(is_admin=True).all()
    
    # Get all standard users
    users = User.query.filter_by(is_admin=False).all()
    
    return render_template('super_admin.html', 
                           admins=admins, 
                           users=users,
                           form=form,
                           delete_user_form=delete_user_form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """
    Gère la page de profil de l'utilisateur.
    
    Returns:
        Rendu du template de profil ou redirection
    """
    form = ProfileForm(obj=current_user)
    form.username.data = current_user.username
    
    # Récupérer les événements où l'utilisateur est inscrit
    registered_events = Event.query.join(Registration).filter(
        Registration.user_id == current_user.id
    ).order_by(Event.date).all()
    
    # Créer un formulaire de désinscription
    unregister_form = UnregisterEventForm()

    if form.validate_on_submit():
        # Mise à jour du profil
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.phone = form.phone.data
        
        # Mise à jour du mot de passe UNIQUEMENT si un nouveau mot de passe est fourni
        if form.new_password.data:
            current_user.password_hash = generate_password_hash(form.new_password.data)
        
        try:
            db.session.commit()
            flash('Profil mis à jour avec succès !', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erreur lors de la mise à jour : {str(e)}', 'danger')
    
    return render_template('profile.html', 
                           user=current_user, 
                           form=form, 
                           registered_events=registered_events,
                           unregister_form=unregister_form)

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Vérifier si l'utilisateur est connecté et déjà inscrit
    user_registrations = []
    form = None
    
    if current_user.is_authenticated:
        user_registrations = [reg.event_id for reg in current_user.registrations]
        
        # Créer le formulaire de désinscription si l'utilisateur est inscrit
        if event_id in user_registrations:
            form = UnregisterEventForm()
    
    # Récupérer les inscriptions pour cet événement
    registrations = Registration.query.filter_by(event_id=event_id).all()
    
    return render_template('event_detail.html', 
                           event=event, 
                           registrations=registrations,
                           user_registrations=user_registrations,
                           form=form)

@app.route('/event/register/<int:event_id>', methods=['GET', 'POST'])
@login_required
def register_event(event_id):
    """
    Inscription d'un utilisateur à un événement avec gestion de la capacité.
    
    Args:
        event_id (int): Identifiant de l'événement
    
    Returns:
        Redirection vers la page appropriée
    """
    event = Event.query.get_or_404(event_id)
    
    # Vérifier si l'événement est actif
    if not event.is_active:
        flash('Cet événement n\'est plus disponible.', 'danger')
        return redirect(request.referrer or url_for('index'))
    
    # Vérifier si l'utilisateur est déjà inscrit
    existing_registration = Registration.query.filter_by(
        user_id=current_user.id, 
        event_id=event_id
    ).first()
    
    if existing_registration:
        flash('Vous êtes déjà inscrit à cet événement', 'danger')
        return redirect(request.referrer or url_for('index'))
    
    # Vérifier la capacité de l'événement
    if not event.is_registration_possible():
        flash('Désolé, cet événement est complet.', 'danger')
        return redirect(request.referrer or url_for('index'))
    
    # Créer une nouvelle inscription
    new_registration = Registration(
        user_id=current_user.id, 
        event_id=event_id
    )
    
    try:
        db.session.add(new_registration)
        db.session.commit()
        
        # Récupérer le nombre de places restantes
        remaining_spots = event.get_remaining_spots()
        
        # Message personnalisé selon les places restantes
        if remaining_spots is not None:
            if remaining_spots > 0:
                flash(f'Inscription réussie ! Il reste {remaining_spots} place(s) disponible(s).', 'success')
            else:
                flash('Inscription réussie ! L\'événement est maintenant complet.', 'success')
        else:
            flash('Inscription réussie !', 'success')
        
        return redirect(request.referrer or url_for('index'))
    
    except Exception as e:
        db.session.rollback()
        flash(f'Erreur lors de l\'inscription : {str(e)}', 'danger')
        return redirect(request.referrer or url_for('index'))

@app.route('/event/unregister/<int:event_id>', methods=['POST', 'GET'])
@login_required
def unregister_event(event_id):
    # Diagnostic ULTRA COMPLET
    print("🚨 DIAGNOSTIC COMPLET DE LA ROUTE DE DÉSINSCRIPTION 🚨")
    print(f"📍 ID Événement : {event_id}")
    print(f"👤 Utilisateur connecté : {current_user.username}")
    print(f"🔍 Méthode de requête : {request.method}")
    print(f"📋 Données de requête : {dict(request.form)}")
    print(f"🌐 Headers : {dict(request.headers)}")
    print(f"🔑 Session : {dict(session)}")
    
    # Vérifier si l'événement existe
    try:
        event = Event.query.get_or_404(event_id)
        print(f"✅ Événement trouvé : {event.title}")
    except Exception as e:
        print(f"❌ Erreur lors de la recherche de l'événement : {str(e)}")
        flash('Événement non trouvé', 'danger')
        return redirect(url_for('index'))
    
    # Vérifier si l'utilisateur est inscrit à l'événement
    try:
        registration = Registration.query.filter_by(
            user_id=current_user.id, 
            event_id=event_id
        ).first()
        
        if not registration:
            print(f"❌ Aucune inscription trouvée pour l'événement {event_id}")
            flash('Vous n\'êtes pas inscrit à cet événement', 'danger')
            return redirect(url_for('index'))
        
        # Supprimer l'inscription
        db.session.delete(registration)
        db.session.commit()
        
        print(f"✅ Désinscription réussie pour l'événement {event_id}")
        flash('Vous avez été désinscrit de l\'événement', 'success')
        return redirect(url_for('index'))
    
    except Exception as e:
        print(f"❌ Erreur lors de la désinscription : {str(e)}")
        db.session.rollback()
        flash('Erreur lors de la désinscription', 'danger')
        return redirect(url_for('index'))

@app.route('/events')
@login_required
def list_events():
    """
    Route pour lister les événements archivés.
    Accessible uniquement aux admins et super admins.
    """
    # Vérifier les permissions
    if not (current_user.is_admin):
        flash('Vous n\'avez pas la permission de voir les événements archivés.', 'danger')
        return redirect(url_for('index'))
    
    # Récupérer les événements archivés
    archived_events = Event.query.filter(Event.is_active == False).order_by(Event.date.desc()).all()
    
    return render_template('events.html', 
                           archived_events=archived_events)

@app.route('/event/archive/<int:event_id>', methods=['POST'])
@login_required
def archive_event(event_id):
    """
    Route pour archiver/désarchiver un événement (réservée aux admins et super admins).
    
    Args:
        event_id (int): Identifiant de l'événement
    
    Returns:
        Redirection vers la page de liste des événements
    """
    form = ArchiveEventForm()
    
    if not (current_user.is_admin or current_user.is_superadmin):
        flash('Vous n\'avez pas les droits pour archiver un événement', 'danger')
        return redirect(url_for('index'))
    
    if form.validate_on_submit():
        event = Event.query.get_or_404(event_id)
        
        try:
            # Inverser le statut actif de l'événement
            event.is_active = not event.is_active
            db.session.commit()
            
            status = 'archivé' if not event.is_active else 'réactivé'
            flash(f'L\'événement a été {status} avec succès.', 'success')
            return redirect(url_for('list_events'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Erreur lors de l\'archivage : {str(e)}', 'danger')
            return redirect(url_for('list_events'))
    
    flash('Erreur de validation du formulaire', 'danger')
    return redirect(url_for('list_events'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

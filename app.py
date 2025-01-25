from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateTimeField, FloatField, IntegerField
from wtforms.validators import DataRequired, Email, Length, ValidationError, Regexp, Optional, URL
import re
from wtforms.validators import NumberRange

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['GOOGLE_MAPS_API_KEY'] = 'AIzaSyBgr-XvksV_FShQH-I99HySlKRlSvc2pAM'  # Placez votre clé API Google Maps ici
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class ProfileForm(FlaskForm):
    """
    Formulaire de profil utilisateur avec validation de téléphone optionnelle.
    """
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
    events = Event.query.filter(Event.is_active == True).order_by(Event.date.desc()).all()
    user_registrations = []
    
    if current_user.is_authenticated:
        # Récupérer les événements où l'utilisateur est inscrit, même archivés
        user_registrations = [reg.event_id for reg in current_user.registrations]
    
    return render_template('index.html', events=events, user_registrations=user_registrations)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
            
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    user_registrations = []
    
    if current_user.is_authenticated:
        user_registrations = [reg.event_id for reg in current_user.registrations]
    
    return render_template('event_detail.html', 
                           event=event, 
                           user_registrations=user_registrations)

@app.route('/event/register/<int:event_id>', methods=['POST'])
@login_required
def register_event(event_id):
    """
    Inscription d'un utilisateur à un événement avec gestion de la capacité.
    
    Args:
        event_id (int): Identifiant de l'événement
    
    Returns:
        Redirection vers la page de détail de l'événement
    """
    event = Event.query.get_or_404(event_id)
    
    # Vérifier si l'événement est actif
    if not event.is_active:
        flash('Cet événement n\'est plus disponible.', 'danger')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Vérifier si l'utilisateur est déjà inscrit
    existing_registration = Registration.query.filter_by(
        user_id=current_user.id, 
        event_id=event_id
    ).first()
    
    if existing_registration:
        flash('Vous êtes déjà inscrit à cet événement', 'danger')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Vérifier la capacité de l'événement
    if not event.is_registration_possible():
        flash('Désolé, cet événement est complet.', 'danger')
        return redirect(url_for('event_detail', event_id=event_id))
    
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
        
        return redirect(url_for('event_detail', event_id=event_id))
    
    except Exception as e:
        db.session.rollback()
        flash(f'Erreur lors de l\'inscription : {str(e)}', 'danger')
        return redirect(url_for('event_detail', event_id=event_id))

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
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action in ['create_admin', 'create_user']:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Check if user already exists
            existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
            if existing_user:
                flash('Un utilisateur avec ce nom ou email existe déjà.', 'danger')
            else:
                new_user = User(
                    username=username, 
                    email=email, 
                    password_hash=generate_password_hash(password),
                    is_admin=action == 'create_admin'
                )
                db.session.add(new_user)
                try:
                    db.session.commit()
                    flash(f'Nouvel {"administrateur" if action == "create_admin" else "utilisateur"} créé avec succès.', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Erreur lors de la création : {str(e)}', 'danger')
        
        elif action == 'modify_admin':
            admin_id = request.form.get('admin_id')
            admin = User.query.get(admin_id)
            
            if admin and admin.username != 'pogoparis':
                # Check if new username or email already exists
                existing_user = User.query.filter(
                    (User.username == request.form.get('username') or 
                     User.email == request.form.get('email')) and 
                    User.id != admin_id
                ).first()
                
                if existing_user:
                    flash('Un utilisateur avec ce nom ou email existe déjà.', 'danger')
                else:
                    admin.username = request.form.get('username')
                    admin.email = request.form.get('email')
                    
                    # Update password only if provided
                    if request.form.get('password'):
                        admin.password_hash = generate_password_hash(request.form.get('password'))
                    
                    try:
                        db.session.commit()
                        flash('Administrateur modifié avec succès.', 'success')
                    except Exception as e:
                        db.session.rollback()
                        flash(f'Erreur lors de la modification de l\'administrateur: {str(e)}', 'danger')
            else:
                flash('Impossible de modifier cet administrateur.', 'danger')
        
        elif action == 'delete_admin':
            admin_id = request.form.get('admin_id')
            admin = User.query.get(admin_id)
            
            if admin and admin.username != 'pogoparis':
                try:
                    # First, delete all registrations associated with this user
                    Registration.query.filter_by(user_id=admin.id).delete()
                    
                    # Then delete the user
                    db.session.delete(admin)
                    db.session.commit()
                    flash('Administrateur supprimé avec succès.', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Erreur lors de la suppression de l\'administrateur: {str(e)}', 'danger')
            else:
                flash('Impossible de supprimer cet administrateur.', 'danger')
        
        elif action == 'modify_user':
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            
            if user:
                # Check if new username or email already exists
                existing_user = User.query.filter(
                    (User.username == request.form.get('username') or 
                     User.email == request.form.get('email')) and 
                    User.id != user_id
                ).first()
                
                if existing_user:
                    flash('Un utilisateur avec ce nom ou email existe déjà.', 'danger')
                else:
                    user.username = request.form.get('username')
                    user.email = request.form.get('email')
                    
                    # Update password only if provided
                    if request.form.get('password'):
                        user.password_hash = generate_password_hash(request.form.get('password'))
                    
                    try:
                        db.session.commit()
                        flash('Utilisateur modifié avec succès.', 'success')
                    except Exception as e:
                        db.session.rollback()
                        flash(f'Erreur lors de la modification de l\'utilisateur: {str(e)}', 'danger')
            else:
                flash('Impossible de modifier cet utilisateur.', 'danger')
        
        elif action == 'delete_user':
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            
            if user:
                try:
                    # First, delete all registrations associated with this user
                    Registration.query.filter_by(user_id=user.id).delete()
                    
                    # Then delete the user
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
    
    return render_template('super_admin.html', admins=admins, users=users)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.phone = form.phone.data
        
        # Gestion du changement de mot de passe
        new_password = form.new_password.data
        if new_password:
            current_user.password_hash = generate_password_hash(new_password)
        
        db.session.commit()
        flash('Profil mis à jour avec succès', 'success')
        return redirect(url_for('profile'))
    
    # Récupérer les événements de l'utilisateur
    user_registrations = Registration.query.filter_by(user_id=current_user.id).all()
    registered_events = [reg.event for reg in user_registrations]
    
    form.first_name.data = current_user.first_name
    form.last_name.data = current_user.last_name
    form.phone.data = current_user.phone
    
    return render_template('profile.html', user=current_user, registered_events=registered_events, form=form)

@app.route('/unregister_event/<int:event_id>', methods=['POST'])
@login_required
def unregister_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Vérifier si l'événement est passé
    if event.is_past_event:
        flash('Impossible de se désinscrire d\'un événement passé', 'danger')
        return redirect(url_for('index'))
    
    # Trouver l'inscription existante
    registration = Registration.query.filter_by(
        user_id=current_user.id, 
        event_id=event_id
    ).first()
    
    if registration:
        db.session.delete(registration)
        db.session.commit()
        flash('Vous avez été désinscrit de l\'événement', 'success')
    else:
        flash('Vous n\'êtes pas inscrit à cet événement', 'danger')
    
    return redirect(url_for('event_detail', event_id=event_id))

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

@app.route('/event/<int:event_id>/archive', methods=['POST'])
@login_required
def archive_event(event_id):
    """
    Route pour archiver/désarchiver un événement (réservée aux admins et super admins).
    """
    # Vérifier les permissions
    if not (current_user.is_admin):
        flash('Vous n\'avez pas la permission de modifier le statut des événements.', 'danger')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Récupérer l'événement
    event = Event.query.get_or_404(event_id)
    
    # Inverser le statut d'archivage
    event.is_active = not event.is_active
    
    # Ajouter un message personnalisé
    action = "archivé" if not event.is_active else "désarchivé"
    flash(f'L\'événement "{event.title}" a été {action}.', 'success')
    
    db.session.commit()
    
    # Rediriger vers la page appropriée
    return redirect(url_for('list_events') if not event.is_active else url_for('event_detail', event_id=event_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

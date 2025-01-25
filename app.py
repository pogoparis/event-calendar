from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, FloatField, SelectField, SubmitField, HiddenField, DateTimeField
from wtforms.validators import DataRequired, Optional, ValidationError, Email, Length, Regexp, URL, NumberRange
from datetime import datetime, timedelta
import logging
import re
import os
from dotenv import load_dotenv
from config import Config

load_dotenv()

# Configuration de l'application
app = Flask(__name__)
app.config.from_object(Config)

# Configuration du logging
def setup_logging(app):
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

setup_logging(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.unauthorized_handler
def unauthorized():
    flash('Veuillez vous connecter pour accéder à cette page.', 'info')
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
    phone_regex = r'^(\+33|0)[1-9](\s?[0-9]{2}){4}$'
    if field.data and not re.match(phone_regex, field.data):
        raise ValidationError('Numéro de téléphone invalide. Format attendu : 0612345678 ou +33 6 12 34 56 78')

def validate_date(form, field):
    if field.data:
        date_str = field.data.strip()
        
        if not re.match(r'^\d{2}/\d{2}/\d{4}$', date_str):
            raise ValidationError(ERROR_MESSAGES['date_format'])
        
        try:
            parsed_date = datetime.strptime(date_str, '%d/%m/%Y').date()
            
            if parsed_date < datetime.now().date():
                raise ValidationError(ERROR_MESSAGES['date_past'])
        
        except ValueError:
            raise ValidationError(ERROR_MESSAGES['date_invalid'])

def validate_time(form, field):
    if field.data:
        time_regex = r'^(0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$'
        
        if not re.match(time_regex, field.data):
            raise ValidationError(ERROR_MESSAGES['time_format'])

def validate_capacity(form, field):
    if field.data is not None:
        try:
            value = int(field.data)
            
            if value <= 0:
                raise ValidationError(ERROR_MESSAGES['capacity_positive'])
        except (ValueError, TypeError):
            raise ValidationError(ERROR_MESSAGES['capacity_positive'])

def validate_price(form, field):
    if field.data is not None:
        try:
            value = float(field.data)
            
            if value < 0:
                raise ValidationError(ERROR_MESSAGES['price_non_negative'])
        except (ValueError, TypeError):
            raise ValidationError(ERROR_MESSAGES['price_non_negative'])

def validate_image_url(form, field):
    if field.data:
        # Liste des extensions d'images autorisées
        allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
        
        # Vérifier si l'URL se termine par une extension d'image
        if not any(field.data.lower().endswith(ext) for ext in allowed_extensions):
            raise ValidationError('Veuillez fournir une URL valide se terminant par .jpg, .jpeg, .png, .gif ou .webp')
        
        # Vérifier si l'URL commence par http:// ou https://
        if not field.data.startswith(('http://', 'https://', '/static/')):
            raise ValidationError('L\'URL doit commencer par http://, https:// ou /static/')

def validate_email(form, field):
    email = field.data
    
    if not email:
        raise ValidationError('Email obligatoire')
    
    if '@' not in email:
        raise ValidationError('L\'email doit contenir le symbole @')
    
    try:
        username, domain = email.split('@')
    except ValueError:
        raise ValidationError('Format d\'email invalide')
    
    if not username or not domain:
        raise ValidationError('Veuillez saisir un email complet')
    
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
        if self.phone:
            phone_regex = r'^(\+33|0)[1-9](\s?[0-9]{2}){4}$'
            return bool(re.match(phone_regex, self.phone))
        return True  

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
    image_url = db.Column(db.String(500), nullable=True)  

    @property
    def is_past_event(self):
        return self.date.date() < datetime.now().date()

    def update_active_status(self):
        self.is_active = not self.is_past_event
        db.session.commit()

    def is_registration_possible(self):
        if self.capacity is None:
            return True
        
        current_registrations = self.registrations.count()
        return current_registrations < self.capacity

    def get_registration_count(self):
        return self.registrations.count()

    def get_remaining_spots(self):
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
    username = StringField('Nom d\'utilisateur', render_kw={'readonly': True})
    first_name = StringField('Prénom')
    last_name = StringField('Nom')
    phone = StringField('Téléphone', validators=[validate_phone])
    new_password = PasswordField('Nouveau mot de passe')
    submit = SubmitField('Mettre à jour')

class CreateEventForm(FlaskForm):
    title = StringField('Titre', validators=[
        DataRequired(message='Le titre est obligatoire')
    ])
    description = TextAreaField('Description', validators=[
        DataRequired(message='La description est obligatoire')
    ])
    
    event_date = StringField('Date', validators=[
        DataRequired(message='La date est obligatoire'),
        validate_date
    ])
    event_time = StringField('Heure', validators=[
        DataRequired(message='L\'heure est obligatoire'),
        validate_time
    ])
    
    location = StringField('Lieu', validators=[
        DataRequired(message='Le lieu est obligatoire')
    ])
    address = StringField('Adresse')
    organizer = StringField('Organisateur')
    
    capacity = IntegerField('Capacité', validators=[
        Optional(), 
        validate_capacity
    ])
    price = FloatField('Prix', validators=[
        Optional(), 
        validate_price
    ])
    
    additional_info = TextAreaField('Informations supplémentaires')
    image_url = StringField('URL de l\'image', validators=[Optional(), validate_image_url])  
    submit = SubmitField('Créer l\'événement')

    def validate(self, extra_validators=None):
        result = super().validate(extra_validators)
        
        if result:
            if self.capacity.data is not None:
                try:
                    value = int(self.capacity.data)
                    if value <= 0:
                        self.capacity.errors.append('La capacité doit être un nombre strictement positif')
                        result = False
                except (ValueError, TypeError):
                    self.capacity.errors.append('La capacité doit être un nombre strictement positif')
                    result = False
            
            if self.price.data is not None:
                try:
                    value = float(self.price.data)
                    if value < 0:
                        self.price.errors.append('Le prix doit être un nombre non négatif')
                        result = False
                except (ValueError, TypeError):
                    self.price.errors.append('Le prix doit être un nombre non négatif')
                    result = False
        
        return result

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
        if not super().validate(extra_validators):
            return False
        
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
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), validate_email])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    action = SelectField('Action', choices=[
        ('create_user', 'Créer un utilisateur'), 
        ('create_admin', 'Créer un administrateur')
    ], validators=[DataRequired()])
    submit = SubmitField('Exécuter', render_kw={'id': 'super_admin_submit'})

class DeleteUserForm(FlaskForm):
    user_id = HiddenField('ID Utilisateur', validators=[DataRequired()])
    submit = SubmitField('Supprimer', render_kw={'id': 'delete_user_submit'})

def get_events(show_past=False):
    query = Event.query.filter(
        Event.is_active == True
    )
    
    if not show_past:
        query = query.filter(Event.date >= datetime.now())
    
    query = query.order_by(Event.date.asc())
    
    events = query.all()
    app.logger.info(f"Événements récupérés - Total: {len(events)}")
    for event in events:
        app.logger.info(f"Événement - ID: {event.id}, Titre: {event.title}, Actif: {event.is_active}, Date: {event.date}")
    
    return events

@app.route('/')
def index():
    events = get_events()
    
    app.logger.info(f"Route index - Nombre d'événements à afficher: {len(events)}")
    
    user_registrations = []
    form = None
    
    if current_user.is_authenticated:
        user_registrations = [reg.event_id for reg in current_user.registrations]
        
        form = UnregisterEventForm()
    
    return render_template('index.html', 
                           events=events, 
                           user_registrations=user_registrations,
                           form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
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
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
        if not (username and email and password):
            flash('Tous les champs sont obligatoires', 'danger')
            return render_template('register.html', form=form)
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Ce nom d\'utilisateur est déjà utilisé', 'danger')
            return render_template('register.html', form=form)
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Cet email est déjà utilisé', 'danger')
            return render_template('register.html', form=form)
        
        new_user = User(
            username=username, 
            email=email, 
            password_hash=generate_password_hash(password)
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
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
    logout_user()
    return redirect(url_for('index'))

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    
    user_registrations = []
    form = None
    
    if current_user.is_authenticated:
        user_registrations = [reg.event_id for reg in current_user.registrations]
        
        if event_id in user_registrations:
            form = UnregisterEventForm()
    
    registrations = Registration.query.filter_by(event_id=event_id).all()
    
    return render_template('event_detail.html', 
                           event=event, 
                           registrations=registrations,
                           user_registrations=user_registrations,
                           form=form)

@app.route('/event/register/<int:event_id>', methods=['GET', 'POST'])
@login_required
def register_event(event_id):
    app.logger.info(f"Tentative d'inscription à l'événement {event_id}")
    app.logger.info(f"Méthode de requête : {request.method}")
    app.logger.info(f"Utilisateur connecté : {current_user.username}")
    
    event = Event.query.get_or_404(event_id)
    
    if not event.is_active:
        app.logger.warning(f"Événement {event_id} n'est plus actif")
        flash('Cet événement n\'est plus disponible.', 'danger')
        return redirect(request.referrer or url_for('index'))
    
    existing_registration = Registration.query.filter_by(
        user_id=current_user.id, 
        event_id=event_id
    ).first()
    
    if existing_registration:
        app.logger.warning(f"Utilisateur déjà inscrit à l'événement {event_id}")
        flash('Vous êtes déjà inscrit à cet événement', 'danger')
        return redirect(request.referrer or url_for('index'))
    
    if not event.is_registration_possible():
        app.logger.warning(f"Événement {event_id} complet")
        flash('Désolé, cet événement est complet.', 'danger')
        return redirect(request.referrer or url_for('index'))
    
    new_registration = Registration(
        user_id=current_user.id, 
        event_id=event_id
    )
    
    try:
        db.session.add(new_registration)
        db.session.commit()
        
        remaining_spots = event.get_remaining_spots()
        
        if remaining_spots is not None:
            if remaining_spots > 0:
                app.logger.info(f"Inscription réussie à l'événement {event_id}. Places restantes : {remaining_spots}")
                flash(f'Inscription réussie ! Il reste {remaining_spots} place(s) disponible(s).', 'success')
            else:
                app.logger.info(f"Inscription réussie à l'événement {event_id}. Événement complet")
                flash('Inscription réussie ! L\'événement est maintenant complet.', 'success')
        else:
            app.logger.info(f"Inscription réussie à l'événement {event_id}")
            flash('Inscription réussie !', 'success')
        
        return redirect(request.referrer or url_for('index'))
    
    except Exception as e:
        app.logger.error(f"Erreur lors de l'inscription à l'événement {event_id}: {str(e)}")
        db.session.rollback()
        flash(f'Erreur lors de l\'inscription : {str(e)}', 'danger')
        return redirect(request.referrer or url_for('index'))

@app.route('/event/unregister/<int:event_id>', methods=['POST', 'GET'])
@login_required
def unregister_event(event_id):
    print(" DIAGNOSTIC COMPLET DE LA ROUTE DE DÉSINSCRIPTION ")
    print(f" ID Événement : {event_id}")
    print(f" Utilisateur connecté : {current_user.username}")
    print(f" Méthode de requête : {request.method}")
    print(f" Données de requête : {dict(request.form)}")
    print(f" Headers : {dict(request.headers)}")
    print(f" Session : {dict(session)}")
    
    event = Event.query.get_or_404(event_id)
    print(f" Événement trouvé : {event.title}")
    
    registration = Registration.query.filter_by(
        user_id=current_user.id, 
        event_id=event_id
    ).first()
    
    if not registration:
        print(f" Aucune inscription trouvée pour l'événement {event_id}")
        flash('Vous n\'êtes pas inscrit à cet événement', 'danger')
        return redirect(url_for('index'))
    
    db.session.delete(registration)
    db.session.commit()
    print(f" Désinscription réussie pour l'événement {event_id}")
    flash('Vous avez été désinscrit de l\'événement', 'success')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    users = User.query.filter_by(is_admin=False).all()
    events = Event.query.all()
    return render_template('admin.html', users=users, events=events)

@app.route('/admin/event/create', methods=['GET', 'POST'])
@login_required
def create_event():
    if not current_user.is_admin:
        flash('Vous n\'avez pas les droits pour créer un événement', 'danger')
        return redirect(url_for('index'))
    
    form = CreateEventForm()
    
    if form.validate_on_submit():
        try:
            event_datetime = datetime.strptime(f"{form.event_date.data} {form.event_time.data}", '%d/%m/%Y %H:%M')
            
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
                image_url=form.image_url.data  
            )
            
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
    if not current_user.is_admin:
        flash('Vous n\'avez pas les droits pour modifier cet événement', 'danger')
        return redirect(url_for('index'))
    
    event = Event.query.get_or_404(event_id)
    
    form = EventForm(obj=event)
    
    if form.validate_on_submit():
        try:
            form.populate_obj(event)
            
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
    if not current_user.is_admin or current_user.username != 'pogoparis':
        flash('Vous n\'avez pas les autorisations requises.', 'danger')
        return redirect(url_for('index'))
    
    form = SuperAdminForm()
    delete_user_form = DeleteUserForm()
    
    if form.validate_on_submit():
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
    
    if delete_user_form.validate_on_submit():
        user_id = delete_user_form.user_id.data
        user = User.query.get(user_id)
        
        if user and user.username != 'pogoparis':
            try:
                Registration.query.filter_by(user_id=user.id).delete()
                
                db.session.delete(user)
                db.session.commit()
                flash('Utilisateur supprimé avec succès.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Erreur lors de la suppression de l\'utilisateur: {str(e)}', 'danger')
        else:
            flash('Impossible de supprimer cet utilisateur.', 'danger')
    
    admins = User.query.filter_by(is_admin=True).all()
    
    users = User.query.filter_by(is_admin=False).all()
    
    return render_template('super_admin.html', 
                           admins=admins, 
                           users=users,
                           form=form,
                           delete_user_form=delete_user_form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    form.username.data = current_user.username
    
    registered_events = Event.query.join(Registration).filter(
        Registration.user_id == current_user.id
    ).order_by(Event.date).all()
    
    unregister_form = UnregisterEventForm()

    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.phone = form.phone.data
        
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

@app.route('/events/archived', methods=['GET'])
@login_required
def list_events():
    if not (current_user.is_admin or current_user.username == 'pogoparis'):
        flash('Vous n\'avez pas la permission de voir les événements archivés.', 'danger')
        return redirect(url_for('index'))
    
    archived_events = Event.query.filter(Event.is_active == False).order_by(Event.date.desc()).all()
    
    app.logger.info(f"Nombre d'événements archivés trouvés : {len(archived_events)}")
    for event in archived_events:
        app.logger.info(f"Événement archivé - ID: {event.id}, Titre: {event.title}, Date: {event.date}, Actif: {event.is_active}")
    
    return render_template('events.html', 
                           events=archived_events,
                           title='Événements archivés',
                           is_archived_view=True)

@app.route('/event/archive/<int:event_id>', methods=['POST'])
@login_required
def archive_event(event_id):
    if not (current_user.is_admin or current_user.username == 'pogoparis'):
        flash('Vous n\'avez pas les droits pour archiver un événement', 'danger')
        return redirect(url_for('index'))
    
    event = Event.query.get_or_404(event_id)
    
    app.logger.info(f"Tentative d'archivage - ID: {event.id}, Titre: {event.title}, Statut actuel: {event.is_active}")
    
    event.is_active = not event.is_active
    db.session.commit()
    
    app.logger.info(f"Événement archivé - ID: {event.id}, Titre: {event.title}, Nouveau statut: {event.is_active}")
    
    status = 'archivé' if not event.is_active else 'réactivé'
    flash(f'L\'événement a été {status} avec succès.', 'success')
    return redirect(url_for('list_events'))

def create_super_admin(username='pogoparis', email='admin@example.com', password='AdminPassword123!'):
    """
    Crée un super administrateur rapidement pour le développement et le test.
    
    :param username: Nom d'utilisateur du super admin
    :param email: Email du super admin
    :param password: Mot de passe du super admin
    :return: L'utilisateur créé ou existant
    """
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        print(f"Utilisateur {username} existe déjà.")
        return existing_user
    
    new_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        is_admin=True
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        print(f"Super administrateur {username} créé avec succès !")
        return new_user
    except Exception as e:
        db.session.rollback()
        print(f"Erreur lors de la création du super administrateur : {e}")
        return None

@app.cli.command("create-super-admin")
def cli_create_super_admin():
    """
    Commande CLI pour créer un super administrateur.
    Peut être appelée avec : flask create-super-admin
    """
    with app.app_context():
        create_super_admin()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

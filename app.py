from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateTimeField, FloatField, IntegerField
from wtforms.validators import DataRequired, Email, Length, ValidationError, Regexp, Optional
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
    address = db.Column(db.String(300), nullable=True)  # Champ pour l'adresse complète
    registrations = db.relationship('Registration', backref='event', lazy=True)

    @property
    def is_past_event(self):
        return self.date < datetime.now()

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def validate_phone(form, field):
    """
    Valide un numéro de téléphone français
    Formats acceptés : 
    - +33 6 12 34 56 78
    - 0612345678
    - 06 12 34 56 78
    """
    phone_regex = r'^(\+33|0)[1-9](\s?[0-9]{2}){4}$'
    if field.data and not re.match(phone_regex, field.data):
        raise ValidationError('Numéro de téléphone invalide. Format attendu : 0612345678 ou +33 6 12 34 56 78')

def validate_date(form, field):
    """
    Valide que la date est au format JJ/MM/AAAA et dans le futur
    """
    if field.data:
        # Supprimer les espaces avant et après
        date_str = field.data.strip()
        
        # Vérifier le format exact
        if not re.match(r'^\d{2}/\d{2}/\d{4}$', date_str):
            raise ValidationError('Format de date invalide. Utilisez JJ/MM/AAAA (exemple : 25/01/2025)')
        
        try:
            # Validation du format JJ/MM/AAAA
            parsed_date = datetime.strptime(date_str, '%d/%m/%Y').date()
            
            # Vérifier que la date n'est pas dans le passé
            if parsed_date < datetime.now().date():
                raise ValidationError('La date de l\'événement doit être dans le futur ou aujourd\'hui.')
        
        except ValueError:
            raise ValidationError('Date invalide. Vérifiez que la date existe réellement.')

def validate_time(form, field):
    """
    Valide le format de l'heure
    """
    if field.data:
        try:
            # Convertir la chaîne en heure
            datetime.strptime(field.data, '%H:%M')
        except ValueError:
            raise ValidationError('Format d\'heure invalide. Utilisez HH:MM')

class ProfileForm(FlaskForm):
    first_name = StringField('Prénom')
    last_name = StringField('Nom')
    phone = StringField('Téléphone', validators=[validate_phone])
    new_password = PasswordField('Nouveau mot de passe')
    submit = SubmitField('Mettre à jour')

class CreateEventForm(FlaskForm):
    title = StringField('Titre', validators=[DataRequired(message='Le titre est obligatoire')])
    description = TextAreaField('Description', validators=[DataRequired(message='La description est obligatoire')])
    
    # Champs de date et heure avec validation
    event_date = StringField('Date', validators=[
        DataRequired(message='La date est obligatoire'),
        validate_date
    ])
    event_time = StringField('Heure', validators=[
        DataRequired(message='L\'heure est obligatoire'),
        validate_time
    ])
    
    # Champs avec validation moins stricte
    location = StringField('Lieu', validators=[DataRequired(message='Le lieu est obligatoire')])
    address = StringField('Adresse')
    organizer = StringField('Organisateur')
    
    # Champs numériques optionnels avec validation
    capacity = IntegerField('Capacité', validators=[
        Optional(), 
        NumberRange(min=1, message='La capacité doit être un nombre positif')
    ])
    price = FloatField('Prix', validators=[
        Optional(), 
        NumberRange(min=0, message='Le prix doit être un nombre positif ou zéro')
    ])
    
    additional_info = TextAreaField('Informations supplémentaires')
    submit = SubmitField('Créer l\'événement')

# Utiliser le même formulaire pour la modification
EventForm = CreateEventForm

@app.route('/')
def index():
    events = Event.query.all()
    user_registrations = []
    
    if current_user.is_authenticated:
        user_registrations = [reg.event_id for reg in current_user.registrations]
    
    return render_template('index.html', events=events, user_registrations=user_registrations)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
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

@app.route('/event/register/<int:event_id>')
@login_required
def register_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Vérifier si l'événement est passé
    if event.is_past_event:
        flash('Impossible de s\'inscrire à un événement passé', 'danger')
        return redirect(url_for('index'))
    
    # Vérifier si l'utilisateur est déjà inscrit
    existing_registration = Registration.query.filter_by(
        user_id=current_user.id, 
        event_id=event_id
    ).first()
    
    if existing_registration:
        flash('Vous êtes déjà inscrit à cet événement', 'warning')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Créer une nouvelle inscription
    new_registration = Registration(
        user_id=current_user.id, 
        event_id=event_id
    )
    
    db.session.add(new_registration)
    db.session.commit()
    
    flash('Inscription réussie', 'success')
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
                additional_info=form.additional_info.data
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
    # Only allow access to super admin
    if not current_user.is_admin or current_user.username != 'pogoparis':
        flash('Vous n\'avez pas les autorisations requises.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create_admin':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Check if user already exists
            existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
            if existing_user:
                flash('Un utilisateur avec ce nom ou email existe déjà.', 'error')
            else:
                new_admin = User(
                    username=username, 
                    email=email, 
                    password_hash=generate_password_hash(password),
                    is_admin=True
                )
                db.session.add(new_admin)
                try:
                    db.session.commit()
                    flash('Nouvel administrateur créé avec succès.', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Erreur lors de la création de l\'administrateur: {str(e)}', 'error')
        
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
                    flash('Un utilisateur avec ce nom ou email existe déjà.', 'error')
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
                        flash(f'Erreur lors de la modification de l\'administrateur: {str(e)}', 'error')
            else:
                flash('Impossible de modifier cet administrateur.', 'error')
        
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
                    flash(f'Erreur lors de la suppression de l\'administrateur: {str(e)}', 'error')
            else:
                flash('Impossible de supprimer cet administrateur.', 'error')
    
    # Get all admin users
    admins = User.query.filter_by(is_admin=True).all()
    return render_template('super_admin.html', admins=admins)

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
        flash('Vous n\'êtes pas inscrit à cet événement', 'warning')
    
    return redirect(url_for('event_detail', event_id=event_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

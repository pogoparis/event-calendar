from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, FloatField, SelectField, SubmitField, HiddenField, FileField
from wtforms.validators import DataRequired, Optional, Email, Length, Regexp, URL, NumberRange, ValidationError
from datetime import datetime
import re

def validate_phone(form, field):
    if field.data and not re.match(r'^\+?1?\d{9,15}$', field.data):
        raise ValidationError('Numéro de téléphone invalide')

def validate_date(form, field):
    try:
        # Essayer de parser la date dans les deux formats
        try:
            date = datetime.strptime(field.data, '%Y-%m-%d')
        except ValueError:
            date = datetime.strptime(field.data, '%d/%m/%Y')
        
        if date.date() < datetime.now().date():
            raise ValidationError('La date ne peut pas être dans le passé')
    except ValueError:
        raise ValidationError('Format de date invalide. Utilisez AAAA-MM-JJ')

def validate_time(form, field):
    try:
        datetime.strptime(field.data, '%H:%M')
    except ValueError:
        raise ValidationError('Format d\'heure invalide. Utilisez HH:MM')

def validate_capacity(form, field):
    if field.data is not None and field.data <= 0:
        raise ValidationError('La capacité doit être un nombre positif')

def validate_price(form, field):
    if field.data is not None and field.data < 0:
        raise ValidationError('Le prix ne peut pas être négatif')

def validate_email(form, field):
    if not re.match(r"[^@]+@[^@]+\.[^@]+", field.data):
        raise ValidationError('Adresse email invalide')

class ProfileForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', render_kw={'readonly': True})
    first_name = StringField('Prénom')
    last_name = StringField('Nom')
    phone = StringField('Téléphone', validators=[validate_phone])
    new_password = PasswordField('Nouveau mot de passe')
    submit = SubmitField('Mettre à jour')

class CreateEventForm(FlaskForm):
    title = StringField('Titre', validators=[DataRequired(message='Le titre est obligatoire')])
    description = TextAreaField('Description', validators=[DataRequired(message='La description est obligatoire')])
    event_date = StringField('Date', validators=[DataRequired(message='La date est obligatoire'), validate_date])
    event_time = StringField('Heure', validators=[DataRequired(message='L\'heure est obligatoire'), validate_time])
    location = StringField('Lieu', validators=[DataRequired(message='Le lieu est obligatoire')])
    address = StringField('Adresse')
    organizer = StringField('Organisateur')
    capacity = IntegerField('Capacité', validators=[Optional(), validate_capacity])
    price = FloatField('Prix', validators=[Optional(), validate_price])
    additional_info = TextAreaField('Informations supplémentaires')
    image_file = FileField('Image de l\'événement', validators=[Optional()])
    submit = SubmitField('Créer l\'événement')

EventForm = CreateEventForm

class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Connexion')

class RegisterForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired(message='Nom d\'utilisateur obligatoire')])
    email = StringField('Email', validators=[DataRequired(message='Email obligatoire'), validate_email])
    password = PasswordField('Mot de passe', validators=[DataRequired(message='Mot de passe obligatoire')])
    submit = SubmitField('S\'inscrire')

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
    submit = SubmitField('Créer', render_kw={'id': 'super_admin_submit', 'class': 'btn btn-primary'})

class DeleteUserForm(FlaskForm):
    user_id = HiddenField('ID Utilisateur', validators=[DataRequired()])
    submit = SubmitField('Supprimer', render_kw={'id': 'delete_user_submit'})

class ModifyUserForm(FlaskForm):
    """
    Formulaire pour modifier les informations d'un utilisateur
    """
    user_id = IntegerField('ID Utilisateur', validators=[DataRequired()])
    username = StringField('Nom d\'utilisateur', validators=[
        DataRequired(message='Le nom d\'utilisateur est requis'),
        Length(min=3, max=80, message='Le nom d\'utilisateur doit faire entre 3 et 80 caractères')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='L\'email est requis'),
        Email(message='Email invalide')
    ])
    password = PasswordField('Nouveau mot de passe (optionnel)', validators=[
        Optional(),
        Length(min=6, message='Le mot de passe doit faire au moins 6 caractères')
    ])
    submit = SubmitField('Enregistrer les modifications')

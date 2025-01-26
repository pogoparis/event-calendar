# Importations des bibliothèques et modules nécessaires
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
import logging
import os
import uuid
from datetime import datetime, timedelta
import click
from werkzeug.utils import secure_filename

# Importations des modules spécifiques à l'application
from config import Config
from extensions import db, migrate, login_manager
from models import User, Event, Registration
from forms import (LoginForm, RegisterForm, CreateEventForm, ProfileForm, 
                   UnregisterEventForm, ArchiveEventForm, SuperAdminForm, DeleteUserForm, ModifyUserForm)
from error_handlers import (
    register_error_handlers, 
    log_error, 
    CustomValidationError, 
    DatabaseOperationError
)

def create_app():
    """
    Fonction de création et configuration de l'application Flask.
    
    Cette fonction initialise tous les composants nécessaires de l'application,
    configure les extensions, définit les routes et les gestionnaires.
    
    :return: Instance de l'application Flask configurée
    """
    # Création de l'instance Flask
    app = Flask(__name__)
    app.config.from_object(Config)

    # Configuration du logging
    def setup_logging(app):
        """
        Configure le système de logging pour l'application.
        
        :param app: Instance de l'application Flask
        """
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)

    setup_logging(app)

    # Initialisation des extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    # Enregistrement des gestionnaires d'erreurs
    register_error_handlers(app)

    @login_manager.unauthorized_handler
    def unauthorized():
        """
        Gestionnaire pour les accès non autorisés.
        
        Redirige l'utilisateur vers la page de connexion avec un message.
        """
        log_error('warning', 'Tentative d\'accès non autorisée')
        flash('Veuillez vous connecter pour accéder à cette page.', 'info')
        return redirect(url_for('login'))

    @login_manager.user_loader
    def load_user(user_id):
        """
        Charge un utilisateur à partir de son ID de session.
        
        :param user_id: ID de l'utilisateur
        :return: Objet utilisateur ou None
        """
        try:
            return User.query.get(int(user_id))
        except Exception as e:
            log_error('error', f'Erreur lors du chargement de l\'utilisateur {user_id}', str(e))
            return None

    def get_events(show_past=False):
        """
        Récupère la liste des événements.
        
        :param show_past: Si True, inclut les événements passés
        :return: Liste des événements
        """
        try:
            if show_past:
                return Event.query.order_by(Event.date.desc()).all()
            return Event.query.filter(Event.date >= datetime.now()).order_by(Event.date).all()
        except Exception as e:
            log_error('error', 'Erreur lors de la récupération des événements', str(e))
            return []

    @app.route('/')
    def index():
        """
        Route principale de l'application.
        
        Affiche la liste des événements à venir et passés.
        """
        # Filtrer les événements par type
        all_events = get_events(show_past=True)
        
        # Logs de débogage complets
        print("\n--- DÉBOGAGE ÉVÉNEMENTS ---")
        print(f"Nombre total d'événements : {len(all_events)}")
        print("Détails des événements :")
        for event in all_events:
            print(f"- {event.title}")
            print(f"  Date : {event.date}")
            print(f"  Est passé : {event.is_past_event()}")
            print(f"  Est actif : {event.is_active}")
        
        # Catégoriser les événements
        upcoming_events = [event for event in all_events if not event.is_past_event() and event.is_active]
        past_events = [event for event in all_events if event.is_past_event()]
        
        print("\nÉvénements à venir :")
        for event in upcoming_events:
            print(f"- {event.title} : {event.date}")
        
        print("\nÉvénements passés :")
        for event in past_events:
            print(f"- {event.title} : {event.date}")
        
        # Récupérer les événements inscrits de l'utilisateur
        user_registrations = current_user.get_registered_event_ids() if current_user.is_authenticated else []
        
        print("\n--- DÉBOGAGE ÉVÉNEMENTS INSCRITS ---")
        print(f"Utilisateur authentifié : {current_user.is_authenticated}")
        print(f"Événements inscrits : {user_registrations}")
        
        print("--- FIN DÉBOGAGE ---\n")
        
        return render_template('index.html', 
                               upcoming_events=upcoming_events, 
                               past_events=past_events,
                               user_registrations=user_registrations,
                               datetime=datetime)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
        Route de connexion.
        
        Gère l'authentification des utilisateurs.
        """
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('Connexion réussie!', 'success')
                return redirect(url_for('index'))
            flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')
        return render_template('login.html', form=form)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """
        Route d'inscription.
        
        Permet aux nouveaux utilisateurs de créer un compte.
        """
        form = RegisterForm()
        if form.validate_on_submit():
            existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
            if existing_user:
                flash('Ce nom d\'utilisateur ou email existe déjà', 'error')
            else:
                new_user = User(
                    username=form.username.data,
                    email=form.email.data,
                    password_hash=generate_password_hash(form.password.data)
                )
                db.session.add(new_user)
                db.session.commit()
                flash('Inscription réussie! Connectez-vous.', 'success')
                return redirect(url_for('login'))
        return render_template('register.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        """
        Route de déconnexion.
        
        Déconnecte l'utilisateur actuel.
        """
        logout_user()
        flash('Vous avez été déconnecté.', 'info')
        return redirect(url_for('index'))

    @app.route('/event/<int:event_id>')
    def event_detail(event_id):
        """
        Route de détail d'événement.
        
        Affiche les informations détaillées d'un événement spécifique.
        
        :param event_id: ID de l'événement
        """
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
                               form=form,
                               current_time=datetime.now())

    @app.route('/event/register/<int:event_id>', methods=['GET', 'POST'])
    @login_required
    def register_event(event_id):
        """
        Route d'inscription à un événement.
        
        Permet à un utilisateur connecté de s'inscrire à un événement.
        
        :param event_id: ID de l'événement
        """
        try:
            app.logger.info(f"Tentative d'inscription à l'événement {event_id}")
            app.logger.info(f"Méthode de requête : {request.method}")
            app.logger.info(f"Utilisateur connecté : {current_user.username}")
            
            event = Event.query.get_or_404(event_id)
            
            if not event.is_active:
                log_error('warning', f"Événement {event_id} n'est plus actif")
                raise CustomValidationError('Cet événement n\'est plus disponible.')
            
            existing_registration = Registration.query.filter_by(
                user_id=current_user.id, 
                event_id=event_id
            ).first()
            
            if existing_registration:
                log_error('warning', f"Utilisateur déjà inscrit à l'événement {event_id}")
                raise CustomValidationError('Vous êtes déjà inscrit à cet événement')
            
            if not event.is_registration_possible():
                log_error('warning', f"Événement {event_id} complet")
                raise CustomValidationError('Désolé, cet événement est complet.')
            
            new_registration = Registration(
                user_id=current_user.id, 
                event_id=event_id
            )
            
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
        
        except CustomValidationError as e:
            db.session.rollback()
            flash(str(e), 'danger')
            return redirect(request.referrer or url_for('index'))
        
        except Exception as e:
            db.session.rollback()
            log_error('critical', f"Erreur lors de l'inscription à l'événement {event_id}", str(e))
            flash('Une erreur inattendue est survenue lors de l\'inscription.', 'error')
            return redirect(request.referrer or url_for('index'))

    @app.route('/event/unregister/<int:event_id>', methods=['POST', 'GET'])
    @login_required
    def unregister_event(event_id):
        """
        Route de désinscription d'un événement.
        
        Permet à un utilisateur connecté de se désinscrire d'un événement.
        
        :param event_id: ID de l'événement
        """
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
            return redirect(request.referrer or url_for('index'))
        
        try:
            db.session.delete(registration)
            db.session.commit()
            print(f" Désinscription réussie pour l'événement {event.title}")
            flash(f'Vous avez été désinscrit de l\'événement {event.title}', 'success')
            
            # Rediriger vers la page précédente, ou la page d'accueil si aucune page précédente n'est trouvée
            return redirect(request.referrer or url_for('index'))
        except Exception as e:
            db.session.rollback()
            print(f" Erreur lors de la désinscription : {str(e)}")
            flash('Une erreur est survenue lors de la désinscription', 'danger')
            return redirect(request.referrer or url_for('index'))

    @app.route('/admin')
    @login_required
    def admin():
        """
        Route d'administration.
        
        Affiche la liste des utilisateurs et des événements pour les administrateurs.
        """
        if not current_user.is_admin:
            return redirect(url_for('index'))
        
        users = User.query.filter_by(is_admin=False).all()
        events = Event.query.all()
        return render_template('admin.html', users=users, events=events)

    @app.route('/admin/event/create', methods=['GET', 'POST'])
    @login_required
    def create_event():
        """
        Route de création d'événement.
        
        Permet aux administrateurs de créer de nouveaux événements.
        """
        if not current_user.is_admin:
            flash('Vous n\'avez pas les droits pour créer un événement', 'danger')
            return redirect(url_for('index'))
        
        form = CreateEventForm()
        
        if form.validate_on_submit():
            try:
                # Créer un nouvel événement
                new_event = Event(
                    title=form.title.data,
                    description=form.description.data,
                    date=datetime.strptime(f'{form.event_date.data} {form.event_time.data}', '%d/%m/%Y %H:%M'),
                    location=form.location.data,
                    organizer=form.organizer.data,
                    capacity=form.capacity.data,
                    price=form.price.data,
                    additional_info=form.additional_info.data,
                    address=form.address.data
                )
                
                # Gérer le téléchargement de l'image
                if form.image_file.data:
                    # Générer un nom de fichier unique
                    filename = str(uuid.uuid4()) + '_' + secure_filename(form.image_file.data.filename)
                    file_path = os.path.join('static/uploads/events', filename)
                    
                    # Créer le dossier s'il n'existe pas
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    
                    # Sauvegarder l'image
                    form.image_file.data.save(file_path)
                    
                    # Enregistrer le chemin de l'image
                    new_event.image_url = f'/static/uploads/events/{filename}'
                else:
                    # Image par défaut si aucune image n'est téléchargée
                    new_event.image_url = '/static/images/default/event.jpg'
                
                db.session.add(new_event)
                db.session.commit()
                
                flash('Événement créé avec succès.', 'success')
                return redirect(url_for('event_detail', event_id=new_event.id))
            
            except Exception as e:
                db.session.rollback()
                flash(f'Erreur lors de la création de l\'événement : {str(e)}', 'danger')
        
        return render_template('create_event.html', form=form, edit_mode=False)

    @app.route('/admin/edit_event/<int:event_id>', methods=['GET', 'POST'])
    @login_required
    def edit_event(event_id):
        """
        Route d'édition d'événement.
        
        Permet aux administrateurs de modifier les événements existants.
        
        :param event_id: ID de l'événement
        """
        event = Event.query.get_or_404(event_id)
        
        # Ensure only admin can edit events
        if not current_user.is_admin:
            flash('Vous n\'avez pas les droits pour modifier cet événement.', 'danger')
            return redirect(url_for('index'))
        
        # Préparer le formulaire avec les données existantes de l'événement
        form = CreateEventForm(obj=event)
        
        # Pré-remplir les champs de date et d'heure
        if request.method == 'GET':
            form.event_date.data = event.date.strftime('%d/%m/%Y') if event.date else None
            form.event_time.data = event.date.strftime('%H:%M') if event.date else None
        
        if form.validate_on_submit():
            try:
                # Gérer le téléchargement de l'image
                if form.image_file.data:
                    # Générer un nom de fichier unique
                    filename = str(uuid.uuid4()) + '_' + secure_filename(form.image_file.data.filename)
                    file_path = os.path.join('static/uploads/events', filename)
                    
                    # Créer le dossier s'il n'existe pas
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    
                    # Sauvegarder l'image
                    form.image_file.data.save(file_path)
                    
                    # Enregistrer le chemin de l'image
                    event.image_url = f'/static/uploads/events/{filename}'
                else:
                    # Image par défaut si aucune image n'est téléchargée
                    event.image_url = '/static/images/default/event.jpg'
                
                # Convertir la date et l'heure
                date_str = form.event_date.data
                time_str = form.event_time.data
                
                # Essayer différents formats de date
                date_formats = ['%d/%m/%Y', '%Y-%m-%d']
                date_obj = None
                
                for date_format in date_formats:
                    try:
                        date_obj = datetime.strptime(date_str, date_format)
                        break
                    except ValueError:
                        continue
                
                if not date_obj:
                    raise ValueError(f"Format de date non reconnu : {date_str}")
                
                # Combiner la date et l'heure
                event_datetime = datetime.combine(date_obj.date(), datetime.strptime(time_str, '%H:%M').time())
                
                # Forcer le fuseau horaire si nécessaire
                # Vous pouvez ajuster cela selon vos besoins
                # event_datetime = event_datetime.replace(tzinfo=timezone.utc)
                
                event.date = event_datetime
                
                # Copier les données du formulaire vers l'événement
                form.populate_obj(event)
                
                db.session.commit()
                flash('Événement mis à jour avec succès.', 'success')
                return redirect(url_for('event_detail', event_id=event.id))
            
            except Exception as e:
                db.session.rollback()
                flash(f'Erreur lors de la modification : {str(e)}', 'danger')
        
        return render_template('create_event.html', form=form, event=event, edit_mode=True)

    @app.route('/super_admin', methods=['GET', 'POST'])
    @login_required
    def super_admin():
        """
        Route de super-administration.
        
        Permet aux super-administrateurs de gérer les utilisateurs et les administrateurs.
        """
        try:
            # Vérifier et définir le super administrateur par défaut si nécessaire
            default_super_admin = User.query.filter_by(username='pogoparis').first()
            if default_super_admin and not default_super_admin.is_super_admin:
                default_super_admin.is_super_admin = True
                db.session.commit()

            if not current_user.is_super_admin:
                log_error('warning', 'Tentative d\'accès à la page super admin sans autorisation')
                flash('Vous n\'avez pas les droits d\'accès à cette page.', 'danger')
                return redirect(url_for('index'))

            form = SuperAdminForm()
            delete_user_form = DeleteUserForm()
            modify_user_form = ModifyUserForm()

            # Récupérer les utilisateurs et administrateurs
            users = User.query.filter_by(is_admin=False, is_super_admin=False).all()
            admins = User.query.filter_by(is_admin=True, is_super_admin=False).all()

            if form.validate_on_submit():
                try:
                    # Logique de création d'utilisateur/admin
                    existing_user = User.query.filter(
                        (User.username == form.username.data) | 
                        (User.email == form.email.data)
                    ).first()

                    if existing_user:
                        raise CustomValidationError('Ce nom d\'utilisateur ou email existe déjà')

                    new_user = User(
                        username=form.username.data,
                        email=form.email.data,
                        password_hash=generate_password_hash(form.password.data)
                    )

                    # Définir le rôle en fonction de l'action
                    if form.action.data == 'create_admin':
                        new_user.is_admin = True
                    
                    db.session.add(new_user)
                    db.session.commit()
                    
                    flash(f'{"Administrateur" if new_user.is_admin else "Utilisateur"} créé avec succès', 'success')
                    return redirect(url_for('super_admin'))

                except CustomValidationError as e:
                    db.session.rollback()
                    flash(str(e), 'danger')
                except Exception as e:
                    db.session.rollback()
                    log_error('error', 'Erreur lors de la création d\'un utilisateur', str(e))
                    flash('Une erreur est survenue lors de la création.', 'error')

            return render_template('super_admin.html', 
                                   create_form=form, 
                                   delete_user_form=delete_user_form,
                                   modify_user_form=modify_user_form,
                                   users=users, 
                                   admins=admins)

        except Exception as e:
            log_error('critical', 'Erreur dans la route super_admin', str(e))
            flash('Une erreur inattendue est survenue.', 'error')
            return redirect(url_for('index'))

    @app.route('/profile', methods=['GET', 'POST'])
    @login_required
    def profile():
        """
        Route de profil utilisateur.
        
        Permet aux utilisateurs de modifier leurs informations personnelles.
        """
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
        """
        Route de liste des événements archivés.
        
        Affiche la liste des événements archivés pour les administrateurs.
        """
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
        """
        Route d'archivage d'événement.
        
        Permet aux administrateurs d'archiver les événements.
        
        :param event_id: ID de l'événement
        """
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

    @app.cli.command("reset_database")
    def reset_database():
        """
        Commande de réinitialisation de la base de données.
        
        Réinitialise complètement la base de données.
        À utiliser uniquement en développement pour résoudre les problèmes de migration.
        """
        from extensions import db
        from models import User
        import click

        # Supprimer toutes les tables
        db.drop_all()

        # Recréer toutes les tables
        db.create_all()

        # Optionnel : Ajouter des données initiales si nécessaire
        admin_user = User(
            username='admin', 
            email='admin@example.com', 
            password_hash='pbkdf2:sha256:260000$...'  # Mot de passe haché par défaut
        )
        db.session.add(admin_user)
        db.session.commit()

        click.echo("Base de données réinitialisée avec succès.")

    return app

# Création de l'instance d'application
app = create_app()

# Point d'entrée principal
if __name__ == '__main__':
    app.run(debug=True)

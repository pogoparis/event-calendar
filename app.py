from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    registrations = db.relationship('Registration', backref='user', lazy=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    registrations = db.relationship('Registration', backref='event', lazy=True)

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    events = Event.query.all()
    return render_template('index.html', events=events)

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
    return render_template('event_detail.html', event=event)

@app.route('/event/register/<int:event_id>')
@login_required
def register_event(event_id):
    event = Event.query.get_or_404(event_id)
    if not Registration.query.filter_by(user_id=current_user.id, event_id=event_id).first():
        registration = Registration(user_id=current_user.id, event_id=event_id)
        db.session.add(registration)
        db.session.commit()
        flash('Successfully registered for the event!')
    else:
        flash('You are already registered for this event')
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
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        event = Event(
            title=request.form.get('title'),
            description=request.form.get('description'),
            date=datetime.strptime(request.form.get('date'), '%Y-%m-%dT%H:%M')
        )
        db.session.add(event)
        db.session.commit()
        return redirect(url_for('admin'))
    return render_template('create_event.html')

@app.route('/admin/event/edit/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    event = Event.query.get_or_404(event_id)
    
    if request.method == 'POST':
        event.title = request.form.get('title')
        event.description = request.form.get('description')
        
        # Convert date string to datetime
        try:
            event.date = datetime.strptime(request.form.get('date'), '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Format de date invalide.', 'error')
            return render_template('edit_event.html', event=event)
        
        try:
            db.session.commit()
            flash('Événement modifié avec succès.', 'success')
            return redirect(url_for('admin'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erreur lors de la modification de l\'événement: {str(e)}', 'error')
    
    return render_template('edit_event.html', event=event)

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

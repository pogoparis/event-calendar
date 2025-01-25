from app import app, db, User, Event, Registration
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta

def create_sample_data():
    # Remove existing data
    with app.app_context():
        db.session.query(Registration).delete()
        db.session.query(Event).delete()
        db.session.query(User).delete()
        
        # Create admin user if not exists
        existing_admin = User.query.filter_by(username='admin').first()
        if not existing_admin:
            admin = User(
                username='admin', 
                email='admin@example.com', 
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
        
        # Create pogoparis super admin if not exists
        existing_super_admin = User.query.filter_by(username='pogoparis').first()
        if not existing_super_admin:
            super_admin = User(
                username='pogoparis',
                email='pogoparis@example.com',
                password_hash=generate_password_hash('SuperAdmin2024!'),
                is_admin=True
            )
            db.session.add(super_admin)
        
        # Create sample events
        events = [
            Event(
                title='Conférence Tech 2024', 
                description='Conférence annuelle sur les dernières technologies', 
                date=datetime.now() + timedelta(days=30)
            ),
            Event(
                title='Atelier de Développement Web', 
                description='Atelier pratique de développement web pour débutants', 
                date=datetime.now() + timedelta(days=45)
            ),
            Event(
                title='Hackathon Paris', 
                description='Compétition de programmation de 48h', 
                date=datetime.now() + timedelta(days=60)
            )
        ]
        
        for event in events:
            db.session.add(event)
        
        try:
            db.session.commit()
            print("Données exemple créées avec succès!")
            print("Compte admin créé - Username: admin, Password: admin123")
        except Exception as e:
            db.session.rollback()
            print(f"Erreur lors de la création des données: {e}")

def create_super_admin():
    # Check if pogoparis user already exists
    with app.app_context():
        existing_user = User.query.filter_by(username='pogoparis').first()
        if not existing_user:
            super_admin = User(
                username='pogoparis',
                email='pogoparis@example.com',
                password_hash=generate_password_hash('SuperAdmin2024!'),
                is_admin=True
            )
            db.session.add(super_admin)
            db.session.commit()
            print("Super admin user 'pogoparis' created successfully!")
        else:
            print("Super admin user 'pogoparis' already exists.")

if __name__ == '__main__':
    with app.app_context():
        create_sample_data()
        create_super_admin()

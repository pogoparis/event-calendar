from app import app, db
from app import User, Event, Registration
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta

def create_sample_data():
    # Supprimer les données existantes
    with app.app_context():
        Registration.query.delete()
        Event.query.delete()
        User.query.delete()
        
        # Créer des utilisateurs
        admin_user = User(
            username='admin', 
            email='admin@example.com', 
            password_hash=generate_password_hash('Adm1n_P@ssw0rd_2024!'),
            is_admin=True
        )
        
        super_admin = User(
            username='pogoparis', 
            email='pogoparis@gmail.com', 
            password_hash=generate_password_hash('S3cur3_Sup3rAdm1n_2024!'),
            is_admin=True
        )
        
        db.session.add(admin_user)
        db.session.add(super_admin)
        
        # Créer des événements (passés et futurs)
        events = [
            Event(
                title='Conférence Tech 2024', 
                description='Une conférence internationale sur les dernières innovations technologiques.',
                date=datetime.now() + timedelta(days=30),
                location='Paris Convention Center',
                address='2 Place de la Porte Maillot, 75017 Paris',
                organizer='Tech Innovations Inc.',
                capacity=200,
                price=150.00,
                additional_info='Comprend le déjeuner et les pauses café. Dress code: business casual.'
            ),
            Event(
                title='Festival de Musique Électronique', 
                description='Un festival de musique électronique avec les meilleurs DJ internationaux.',
                date=datetime.now() + timedelta(days=60),
                location='Stade de France',
                address='93210 Saint-Denis',
                organizer='Electro Events',
                capacity=50000,
                price=80.00,
                additional_info='Camping disponible sur place. Plusieurs scènes et styles musicaux.'
            ),
            Event(
                title='Salon du Livre Ancien', 
                description='Rencontre annuelle des passionnés de livres anciens et de collection.',
                date=datetime.now() - timedelta(days=15),
                location='Bibliothèque Nationale',
                address='11 Rue de Richelieu, 75001 Paris',
                organizer='Association des Bibliophiles',
                capacity=100,
                price=10.00,
                additional_info='Exposition de manuscrits rares. Conférences et dédicaces toute la journée.'
            ),
            Event(
                title='Marathon de Paris', 
                description='Le célèbre marathon traversant les plus beaux quartiers de Paris.',
                date=datetime.now() - timedelta(days=45),
                location='Champs-Élysées',
                address='Avenue des Champs-Élysées, 75008 Paris',
                organizer='Paris Marathon Organization',
                capacity=40000,
                price=120.00,
                additional_info='Parcours de 42,195 km. Médaille et ravitaillement pour tous les participants.'
            )
        ]
        
        db.session.add_all(events)
        db.session.commit()
        
        print("Données exemple créées avec succès!")

if __name__ == '__main__':
    create_sample_data()

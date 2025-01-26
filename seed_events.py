from app import app, db, Event, User, Registration
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
import os
import traceback

def seed_events_with_registrations():
    try:
        with app.app_context():
            print("Début de la création des événements")
            
            # Supprimer tous les événements existants
            db.session.query(Registration).delete()
            db.session.query(Event).delete()
            db.session.query(User).delete()
            db.session.commit()
            print("Tables nettoyées")
            
            # Créer des utilisateurs
            admin = User(
                username='pogoparis',
                email='admin@example.com',
                password_hash=generate_password_hash('AdminPassword123!')
            )
            admin.is_admin = True
            admin.is_super_admin = True
            db.session.add(admin)
            
            utilisateur = User(
                username='utilisateur',
                email='utilisateur@example.com',
                password_hash=generate_password_hash('UserPassword123!')
            )
            utilisateur.is_admin = False
            utilisateur.is_super_admin = False
            db.session.add(utilisateur)
            
            db.session.commit()
            print("Utilisateurs créés")
            
            # Créer un répertoire pour les images d'événements s'il n'existe pas
            os.makedirs('static/uploads/events', exist_ok=True)
            
            # Événements à créer
            events_data = [
                {
                    'title': 'Conférence Tech Innovante',
                    'description': 'Une journée complète dédiée aux dernières innovations technologiques.',
                    'date': datetime.now() + timedelta(days=30),
                    'location': 'Palais des Congrès, Paris',
                    'organizer': 'Tech Innovations Inc.',
                    'capacity': 200,
                    'price': 99.99,
                    'address': '2 Place de la Porte Maillot, 75017 Paris',
                    'is_active': True
                },
                {
                    'title': 'Festival de Musique Électronique',
                    'description': 'Un week-end de musique électronique avec les meilleurs DJ internationaux.',
                    'date': datetime.now() + timedelta(days=60),
                    'location': 'Parc des Expositions, Lyon',
                    'organizer': 'Electro Events',
                    'capacity': 5000,
                    'price': 149.50,
                    'address': 'Rue de la Villette, 69003 Lyon',
                    'is_active': True
                },
                {
                    'title': 'Salon du Vin et des Gastronomies',
                    'description': 'Découvrez les meilleurs vins et produits gastronomiques de France.',
                    'date': datetime.now() + timedelta(days=45),
                    'location': 'Parc des Expositions, Bordeaux',
                    'organizer': 'Bordeaux Wine Association',
                    'capacity': 1000,
                    'price': 25.00,
                    'address': 'Rue Jean Samazeuilh, 33300 Bordeaux',
                    'is_active': True
                },
                {
                    'title': 'Marathon de Paris',
                    'description': 'Le célèbre marathon traversant les plus beaux quartiers de Paris.',
                    'date': datetime.now() + timedelta(days=90),
                    'location': 'Champs-Élysées',
                    'organizer': 'Paris Marathon Organization',
                    'capacity': 40000,
                    'price': 120.00,
                    'address': 'Avenue des Champs-Élysées, 75008 Paris',
                    'is_active': True
                },
                {
                    'title': 'Atelier de Cuisine Française',
                    'description': 'Apprenez à cuisiner des plats traditionnels français avec un chef renommé.',
                    'date': datetime.now() + timedelta(days=75),
                    'location': 'École de Cuisine Paris',
                    'organizer': 'École Culinaire Française',
                    'capacity': 20,
                    'price': 75.50,
                    'address': '12 Rue de la Cuisine, 75001 Paris',
                    'is_active': True
                }
            ]
            
            # Créer les événements
            for event_info in events_data:
                event = Event(**event_info)
                db.session.add(event)
                print(f"Événement ajouté : {event.title}")
            
            db.session.commit()
            print("Tous les événements ont été ajoutés avec succès")
    
    except Exception as e:
        print("Erreur lors de la création des événements :")
        print(traceback.format_exc())
        db.session.rollback()

if __name__ == '__main__':
    seed_events_with_registrations()

from app import app, db, Event, User, Registration
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
import os
from PIL import Image, ImageDraw, ImageFont

def seed_events_with_registrations():
    with app.app_context():
        # Supprimer les données existantes
        db.session.query(Registration).delete()
        db.session.query(Event).delete()
        
        # Créer des utilisateurs si nécessaire
        admin = User.query.filter_by(username='pogoparis').first()
        if not admin:
            admin = User(
                username='pogoparis',
                email='admin@example.com',
                password_hash=generate_password_hash('AdminPassword123!')
            )
            admin.is_admin = True
            admin.is_super_admin = True
            db.session.add(admin)
        
        utilisateur = User.query.filter_by(username='utilisateur').first()
        if not utilisateur:
            utilisateur = User(
                username='utilisateur',
                email='utilisateur@example.com',
                password_hash=generate_password_hash('UserPassword123!')
            )
            utilisateur.is_admin = False
            utilisateur.is_super_admin = False
            db.session.add(utilisateur)
        
        db.session.commit()
        
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
                'is_active': True,
                'image_filename': 'tech_conference.jpg'
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
                'is_active': True,
                'image_filename': 'electro_festival.jpg'
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
                'is_active': True,
                'image_filename': 'wine_salon.jpg'
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
                'is_active': True,
                'image_filename': 'paris_marathon.jpg'
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
                'is_active': True,
                'image_filename': 'cuisine_francaise.jpg'
            }
        ]
        
        def create_placeholder_image(filename, event_title):
            # Créer un répertoire pour les images d'événements s'il n'existe pas
            os.makedirs('static/uploads/events', exist_ok=True)
            
            # Créer une image de placeholder
            img = Image.new('RGB', (800, 400), color=(73, 109, 137))
            d = ImageDraw.Draw(img)
            
            # Charger une police
            try:
                font_title = ImageFont.truetype("arial.ttf", 40)
            except IOError:
                font_title = ImageFont.load_default()
            
            # Dessiner le titre de l'événement
            d.text((50, 150), event_title, font=font_title, fill=(255, 255, 255))
            
            # Sauvegarder l'image
            img.save(f'static/uploads/events/{filename}')
        
        # Créer les événements
        created_events = []
        for event_info in events_data:
            # Créer l'image de placeholder
            create_placeholder_image(event_info['image_filename'], event_info['title'])
            
            # Créer l'événement
            event = Event(
                title=event_info['title'],
                description=event_info['description'],
                date=event_info['date'],
                location=event_info['location'],
                organizer=event_info['organizer'],
                capacity=event_info['capacity'],
                price=event_info['price'],
                address=event_info['address']
            )
            event.is_active = event_info['is_active']
            event.image_url = f'/static/uploads/events/{event_info["image_filename"]}'
            
            db.session.add(event)
            created_events.append(event)
        
        db.session.commit()
        print("Événements et inscriptions ajoutés avec succès !")

if __name__ == '__main__':
    seed_events_with_registrations()

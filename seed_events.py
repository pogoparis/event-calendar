from app import app, db, Event, User, Registration
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
import os

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
        
        # Créer des images de placeholder si elles n'existent pas
        os.makedirs('static/uploads/events', exist_ok=True)
        
        # Événements à créer
        events_data = [
            {
                'title': 'Conférence Tech Passée',
                'description': 'Une conférence technologique qui a eu lieu récemment',
                'date': datetime.now() - timedelta(days=30),
                'location': 'Station F, Paris',
                'organizer': 'Tech Innovators',
                'capacity': 5,
                'price': 50,
                'address': '55 Boulevard Vincent Auriol, 75013 Paris',
                'is_active': False,
                'image_filename': 'past_conference.jpg'
            },
            {
                'title': 'Atelier IA Archivé',
                'description': 'Découvrez les dernières avancées en Intelligence Artificielle',
                'date': datetime.now() + timedelta(days=60),
                'location': 'NUMA, Paris',
                'organizer': 'AI Lab',
                'capacity': 5,
                'price': 75,
                'address': '39 Rue du Caire, 75002 Paris',
                'is_active': False,
                'image_filename': 'ai_workshop.jpg'
            },
            {
                'title': 'Hackathon Développement Durable',
                'description': 'Hackathon sur les solutions innovantes pour le développement durable',
                'date': datetime.now() + timedelta(days=15),
                'location': 'Le Wagon, Paris',
                'organizer': 'Green Tech',
                'capacity': 5,
                'price': 0,
                'address': '16 Villa Gaudelet, 75011 Paris',
                'is_active': True,
                'image_filename': 'hackathon.jpg'
            },
            {
                'title': 'Soirée Networking Tech',
                'description': 'Rencontrez les professionnels de la tech et développez votre réseau',
                'date': datetime.now() + timedelta(days=30),
                'location': 'WeWork, Paris',
                'organizer': 'Tech Community',
                'capacity': 5,
                'price': 25,
                'address': '7 Rue de Madrid, 75008 Paris',
                'is_active': True,
                'image_filename': 'networking.jpg'
            },
            {
                'title': 'Atelier Entrepreneuriat',
                'description': 'Apprenez les bases de la création et du développement d\'entreprise',
                'date': datetime.now() + timedelta(days=45),
                'location': 'Paris&Co, Paris',
                'organizer': 'Startup School',
                'capacity': 5,
                'price': 40,
                'address': '50 Rue de Turbigo, 75003 Paris',
                'is_active': True,
                'image_filename': 'entrepreneurship.jpg'
            }
        ]
        
        # Créer des images de placeholder
        from PIL import Image, ImageDraw, ImageFont
        
        def create_placeholder_image(filename, title):
            image = Image.new('RGB', (1200, 800), color='white')
            draw = ImageDraw.Draw(image)
            
            try:
                font_title = ImageFont.truetype("arial.ttf", 80)
                font_subtitle = ImageFont.truetype("arial.ttf", 50)
            except IOError:
                font_title = ImageFont.load_default()
                font_subtitle = ImageFont.load_default()
            
            draw.text((100, 300), title, fill='black', font=font_title)
            draw.text((100, 450), "Événement PogoParis", fill='gray', font=font_subtitle)
            
            image.save(f'static/uploads/events/{filename}')
        
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
        
        # Ajouter des inscriptions pour certains événements
        for event in created_events[:3]:  # Ajouter des inscriptions pour 3 événements
            for _ in range(5):  # 5 inscriptions par événement
                registration = Registration(
                    user_id=utilisateur.id,
                    event_id=event.id
                )
                db.session.add(registration)
        
        db.session.commit()
        
        print("Événements et inscriptions ajoutés avec succès !")

if __name__ == '__main__':
    seed_events_with_registrations()

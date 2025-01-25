from app import app, db
from app import Event
from datetime import datetime, timedelta

with app.app_context():
    # Liste des événements de démonstration
    demo_events = [
        {
            'title': 'Conférence Tech Innovante',
            'description': 'Une journée complète dédiée aux dernières innovations technologiques.',
            'date': datetime.now() + timedelta(days=30),
            'location': 'Palais des Congrès, Paris',
            'address': '2 Place de la Porte Maillot, 75017 Paris',
            'organizer': 'Tech Innovations Inc.',
            'capacity': 200,
            'price': 99.99,
            'additional_info': 'Networking, présentations de startups, et démonstrations de technologies de pointe.',
            'image_url': 'https://example.com/tech-conference.jpg'
        },
        {
            'title': 'Festival de Musique Électronique',
            'description': 'Un week-end de musique électronique avec les meilleurs DJ internationaux.',
            'date': datetime.now() + timedelta(days=60),
            'location': 'Parc des Expositions, Lyon',
            'address': 'Rue de la Villette, 69003 Lyon',
            'organizer': 'Electro Events',
            'capacity': 5000,
            'price': 149.50,
            'additional_info': 'Plusieurs scènes, camping sur place, food trucks et bars.',
            'image_url': 'https://example.com/electro-festival.jpg'
        },
        {
            'title': 'Salon du Vin et des Gastronomies',
            'description': 'Découvrez les meilleurs vins et produits gastronomiques de France.',
            'date': datetime.now() + timedelta(days=45),
            'location': 'Parc des Expositions, Bordeaux',
            'address': 'Rue Jean Samazeuilh, 33300 Bordeaux',
            'organizer': 'Bordeaux Wine Association',
            'capacity': 1000,
            'price': 25.00,
            'additional_info': 'Dégustation, rencontres avec des vignerons, ateliers culinaires.',
            'image_url': 'https://example.com/wine-salon.jpg'
        }
    ]

    # Ajouter les événements
    for event_data in demo_events:
        existing_event = Event.query.filter_by(title=event_data['title']).first()
        if not existing_event:
            new_event = Event(**event_data)
            db.session.add(new_event)
    
    db.session.commit()
    print("Événements de démonstration créés avec succès !")

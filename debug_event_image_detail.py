from app import create_app
from models import Event, db
import os

app = create_app()

with app.app_context():
    event = Event.query.get(5)
    print(f"Image URL from database: {event.image_url}")
    
    # Chemins à vérifier
    paths_to_check = [
        os.path.join('static', event.image_url.replace('/static/', '')),
        os.path.join('C:/Users/Administrateur/CascadeProjects/event_manager', event.image_url.replace('/static/', '')),
        os.path.join('static', 'uploads', 'events', os.path.basename(event.image_url.replace('/static/uploads/events/', ''))),
        event.image_url
    ]
    
    print("\nChecking paths:")
    for path in paths_to_check:
        print(f"{path}: {os.path.exists(path)}")

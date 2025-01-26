from app import create_app
from models import Event, db
import os

app = create_app()

with app.app_context():
    event = Event.query.get(4)
    print(f"Image URL: {event.image_url}")
    print(f"Exists in static: {os.path.exists(os.path.join('static', event.image_url)) if event.image_url else 'No image URL'}")
    print(f"Exists in static/images/events: {os.path.exists(os.path.join('static', 'images', 'events', event.image_url)) if event.image_url else 'No image URL'}")

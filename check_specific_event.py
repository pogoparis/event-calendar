from app import app, db
from models import Event
from datetime import datetime

with app.app_context():
    event = Event.query.get(3)  # L'événement avec ID 3
    print(f"Événement : {event.title}")
    print(f"Date de l'événement : {event.date}")
    print(f"Est-ce un événement passé ? {event.is_past_event()}")

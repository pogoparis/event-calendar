from app import app, db
from models import Event

with app.app_context():
    events = Event.query.all()
    for event in events:
        print(f"{event.id}: {event.title} - {event.date} - Past: {event.is_past_event()}")

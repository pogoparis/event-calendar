from app import app, db, Event

with app.app_context():
    events = Event.query.all()
    for event in events:
        print(f"Événement : {event.title}")
        print("---")

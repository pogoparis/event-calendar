from app import app, db, Event

with app.app_context():
    events = Event.query.all()
    print(f"Nombre d'événements : {len(events)}")
    for event in events:
        print(event.title)

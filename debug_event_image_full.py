from app import create_app
from models import Event, db
import os
import sys

app = create_app()

with app.app_context():
    event = Event.query.get(5)
    print(f"Event ID: {event.id}")
    print(f"Image URL from database: {event.image_url}")
    
    # Chemins de base
    base_paths = [
        'static',
        'C:/Users/Administrateur/CascadeProjects/event_manager/static'
    ]
    
    # Extraire le nom de fichier
    filename = os.path.basename(event.image_url.replace('/static/uploads/events/', ''))
    
    # Liste des chemins possibles à vérifier
    possible_paths = []
    for base_path in base_paths:
        possible_paths.extend([
            os.path.join(base_path, 'uploads', 'events', filename),
            os.path.join(base_path, 'uploads', 'events', os.path.basename(filename)),
            os.path.join(base_path, event.image_url.replace('/static/', ''))
        ])
    
    print("\nChecking paths:")
    for path in possible_paths:
        print(f"{path}: {os.path.exists(path)}")
        if os.path.exists(path):
            print(f"  Full absolute path: {os.path.abspath(path)}")
    
    # Vérifier le contenu du répertoire
    upload_dir = 'static/uploads/events'
    print(f"\nContents of {upload_dir}:")
    try:
        for item in os.listdir(upload_dir):
            print(f"  {item}")
    except Exception as e:
        print(f"Error listing directory: {e}")
    
    # Vérifier les permissions
    print("\nFile permissions:")
    for path in possible_paths:
        try:
            if os.path.exists(path):
                print(f"{path}: readable = {os.access(path, os.R_OK)}")
        except Exception as e:
            print(f"Error checking {path}: {e}")

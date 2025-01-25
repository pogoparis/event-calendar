import os
import shutil

# Créer le répertoire s'il n'existe pas
os.makedirs('static/images/events', exist_ok=True)

# Liste des images à copier
images = [
    {
        'source': 'static/images/events/sport.jpg',
        'destination': 'static/images/events/tech-conference.jpg'
    },
    {
        'source': 'static/images/events/food.jpg',
        'destination': 'static/images/events/wine-salon.jpg'
    },
    {
        'source': 'static/images/events/art.jpg',
        'destination': 'static/images/events/electro-festival.jpg'
    },
    {
        'source': 'static/images/default-event.jpg',
        'destination': 'static/images/events/default-event.jpg'
    }
]

# Copier chaque image
for image in images:
    try:
        # Vérifier si le fichier source existe
        if os.path.exists(image['source']):
            shutil.copy2(image['source'], image['destination'])
            print(f"Copie réussie : {image['source']} -> {image['destination']}")
        else:
            print(f"Fichier source non trouvé : {image['source']}")
    except Exception as e:
        print(f"Erreur lors de la copie de {image['source']} : {e}")

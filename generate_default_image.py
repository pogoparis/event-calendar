from PIL import Image, ImageDraw, ImageFont
import os

def create_default_event_image():
    # Créer le dossier s'il n'existe pas
    os.makedirs('static/images', exist_ok=True)
    
    # Créer une nouvelle image avec un fond blanc
    image = Image.new('RGB', (1200, 800), color='white')
    
    # Créer un contexte de dessin
    draw = ImageDraw.Draw(image)
    
    # Charger une police
    try:
        font_title = ImageFont.truetype("arial.ttf", 80)
        font_subtitle = ImageFont.truetype("arial.ttf", 50)
    except IOError:
        font_title = ImageFont.load_default()
        font_subtitle = ImageFont.load_default()
    
    # Dessiner le titre
    draw.text((100, 300), "Événement PogoParis", fill='black', font=font_title)
    draw.text((100, 450), "Aucune image disponible", fill='gray', font=font_subtitle)
    
    # Sauvegarder l'image
    image.save('static/images/default-event.jpg')
    print("Image par défaut créée avec succès !")

if __name__ == '__main__':
    create_default_event_image()

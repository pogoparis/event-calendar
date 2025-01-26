from PIL import Image, ImageDraw, ImageFont
import os

def create_placeholder_image(filename, title):
    # Create a new image with a white background
    image = Image.new('RGB', (1200, 800), color='white')
    
    # Create a drawing context
    draw = ImageDraw.Draw(image)
    
    # Load a font
    try:
        font_title = ImageFont.truetype("arial.ttf", 80)
        font_subtitle = ImageFont.truetype("arial.ttf", 50)
    except IOError:
        font_title = ImageFont.load_default()
        font_subtitle = ImageFont.load_default()
    
    # Draw title
    draw.text((100, 300), title, fill='black', font=font_title)
    draw.text((100, 450), "Événement PogoParis", fill='gray', font=font_subtitle)
    
    # Save the image
    image.save(filename)

# Ensure the directory exists
os.makedirs('static/uploads/events', exist_ok=True)

# Create placeholder images
create_placeholder_image('static/uploads/events/networking.jpg', 'Soirée Networking Tech')
create_placeholder_image('static/uploads/events/ai_workshop.jpg', 'Atelier IA')

print("Placeholder images created successfully!")

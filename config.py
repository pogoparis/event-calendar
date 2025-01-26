import os
from dotenv import load_dotenv

# Charger les variables d'environnement du fichier .env
load_dotenv()

class Config:
    # Clé API Google Maps
    GOOGLE_MAPS_API_KEY = os.environ.get('GOOGLE_MAPS_API_KEY', '')

    # Autres configurations
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default_secret_key')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///event_manager.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configuration de sécurité
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    
    # Activer le mode débogage par défaut
    DEBUG = True

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

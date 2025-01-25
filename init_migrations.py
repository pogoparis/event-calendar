from app import app, db
from flask_migrate import Migrate, init, migrate as migrate_cmd, upgrade

with app.app_context():
    Migrate(app, db)
    init()
    migrate_cmd(message="Add user profile fields")
    upgrade()
    print("Migrations initialisées et appliquées avec succès !")

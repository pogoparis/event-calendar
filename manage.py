from flask.cli import FlaskGroup
from app import create_app
from extensions import db
from models import User, Event, Registration
import click

app = create_app()

@app.cli.command("reset_database")
def reset_database():
    """
    Réinitialise complètement la base de données.
    À utiliser uniquement en développement pour résoudre les problèmes de migration.
    """
    # Supprimer toutes les tables
    db.drop_all()

    # Recréer toutes les tables
    db.create_all()

    # Optionnel : Ajouter des données initiales si nécessaire
    admin_user = User(username='admin', email='admin@example.com')
    admin_user.set_password('adminpassword')
    db.session.add(admin_user)
    db.session.commit()

    click.echo("Base de données réinitialisée avec succès.")

if __name__ == '__main__':
    app.cli()

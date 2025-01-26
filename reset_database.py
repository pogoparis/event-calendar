from app import app, db, User
from werkzeug.security import generate_password_hash

def reset_database():
    with app.app_context():
        # Supprimer toutes les tables existantes
        db.drop_all()
        
        # Recréer les tables
        db.create_all()
        
        # Créer un super admin
        super_admin = User(
            username='pogoparis',
            email='admin@example.com',
            password_hash=generate_password_hash('AdminPassword123!')
        )
        super_admin.is_admin = True
        super_admin.is_super_admin = True
        
        # Créer un utilisateur standard
        standard_user = User(
            username='utilisateur',
            email='utilisateur@example.com',
            password_hash=generate_password_hash('UserPassword123!')
        )
        standard_user.is_admin = False
        standard_user.is_super_admin = False
        
        # Ajouter les utilisateurs à la session
        db.session.add(super_admin)
        db.session.add(standard_user)
        
        # Valider les changements
        db.session.commit()
        
        print("Base de données réinitialisée avec succès !")
        print("\nUtilisateurs créés :")
        print(f"1. Super Admin - Nom: {super_admin.username}, Email: {super_admin.email}")
        print(f"2. Utilisateur standard - Nom: {standard_user.username}, Email: {standard_user.email}")

if __name__ == '__main__':
    reset_database()

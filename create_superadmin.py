from app import app, db
from app import User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Créer un super admin
    super_admin = User(
        username='superadmin', 
        email='superadmin@example.com', 
        password_hash=generate_password_hash('SuperAdmin2024!'),
        is_admin=True,
        first_name='Super',
        last_name='Admin'
    )
    
    # Vérifier si l'utilisateur existe déjà
    existing_user = User.query.filter_by(username='superadmin').first()
    if existing_user:
        print("Super admin already exists!")
    else:
        db.session.add(super_admin)
        db.session.commit()
        print("Super admin created successfully!")

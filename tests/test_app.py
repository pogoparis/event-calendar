import unittest
from app import app, db, User, Event, Registration, CreateEventForm
from werkzeug.security import generate_password_hash
from flask_login import login_user, current_user

class TestEventManager(unittest.TestCase):
    def setUp(self):
        # Configurer l'application en mode test
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        
        # Créer un contexte d'application
        self.app_context = app.app_context()
        self.app_context.push()
        
        # Recréer toutes les tables
        db.drop_all()
        db.create_all()
        
        # Créer un utilisateur super admin pour les tests
        super_admin = User(
            username='pogoparis', 
            email='pogoparis_test@gmail.com', 
            password_hash=generate_password_hash('S3cur3_Sup3rAdm1n_2024!'),
            is_admin=True
        )
        db.session.add(super_admin)
        
        # Créer un utilisateur de test avec un email unique
        test_user = User(
            username='testuser_unique',
            email='test_unique@example.com',
            password_hash=generate_password_hash('testpassword'),
            is_admin=False
        )
        db.session.add(test_user)
        
        # Valider les ajouts
        db.session.commit()
        
        # Créer un client de test
        self.app = app.test_client()
    
    def tearDown(self):
        # Supprimer la session et le contexte
        db.session.remove()
        self.app_context.pop()
    
    def test_user_registration(self):
        response = self.app.post('/register', data={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpassword'
        }, follow_redirects=True)
        
        self.assertIn(b'Inscription r\xc3\xa9ussie', response.data)
    
    def test_login(self):
        response = self.app.post('/login', data={
            'username': 'testuser_unique',
            'password': 'testpassword'
        }, follow_redirects=True)
        
        self.assertIn(b'\xc3\x89v\xc3\xa9nements', response.data)
    
    def test_admin_access(self):
        # Connexion en tant que super admin
        login_response = self.app.post('/login', data={
            'username': 'pogoparis',
            'password': 'S3cur3_Sup3rAdm1n_2024!'
        }, follow_redirects=True)
        
        # Vérifier que la connexion a réussi
        self.assertIn(b'\xc3\x89v\xc3\xa9nements', login_response.data)
        
        # Accéder à la page super admin
        response = self.app.get('/super_admin', follow_redirects=True)
        self.assertIn(b'Cr\xc3\xa9er un Nouvel Utilisateur', response.data)
    
    def test_create_event(self):
        # Connexion en tant qu'admin
        login_response = self.app.post('/login', data={
            'username': 'pogoparis',
            'password': 'S3cur3_Sup3rAdm1n_2024!'
        }, follow_redirects=True)
        
        # Vérifier que la connexion a réussi
        self.assertIn(b'\xc3\x89v\xc3\xa9nements', login_response.data)
        
        # Créer un événement
        response = self.app.post('/admin/event/create', data={
            'title': 'Test Event',
            'description': 'A test event for unit testing',
            'event_date': '31/12/2025',
            'event_time': '19:00',
            'location': 'Test Location',
            'capacity': 50,
            'price': 10.0
        }, follow_redirects=True)
        
        # Vérifier que l'événement a été créé
        self.assertIn(b'Test Event', response.data)
        self.assertIn(b'Test Location', response.data)

if __name__ == '__main__':
    unittest.main()

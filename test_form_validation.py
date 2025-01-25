import unittest
from app import app, CreateEventForm, db
from datetime import datetime, timedelta
from flask import current_app

# Configuration spécifique aux tests
app.config['WTF_CSRF_ENABLED'] = False
app.config['SECRET_KEY'] = 'test_secret_key'

class TestEventFormValidation(unittest.TestCase):
    def setUp(self):
        """Prépare un formulaire vide avant chaque test"""
        self.app_context = app.app_context()
        self.app_context.push()
        self.form = CreateEventForm()

    def tearDown(self):
        """Nettoie le contexte d'application après chaque test"""
        self.app_context.pop()

    def _prepare_base_form(self):
        """Prépare un formulaire de base valide"""
        self.form.title.data = 'Titre Test'
        self.form.description.data = 'Description Test'
        self.form.event_date.data = (datetime.now() + timedelta(days=30)).strftime('%d/%m/%Y')
        self.form.event_time.data = '14:30'
        self.form.location.data = 'Lieu Test'

    def test_optional_fields(self):
        """Teste les champs optionnels"""
        # Tester la capacité
        capacity_test_cases = [
            (0, False, "La capacité doit être un nombre strictement positif"),
            (1, True, None),
            (-1, False, "La capacité doit être un nombre strictement positif")
        ]

        for value, expected_validity, expected_error in capacity_test_cases:
            self._prepare_base_form()
            self.form.capacity.data = value

            validation_result = self.form.validate()
            
            print(f"\nTesting capacity: {value}")
            print(f"Form data: {self.form.data}")
            print(f"Validation result: {validation_result}")
            print(f"Form errors: {self.form.errors}")
            
            if not validation_result:
                print("Capacity field errors:", self.form.capacity.errors)
            
            self.assertEqual(validation_result, expected_validity, 
                             f"Échec pour la capacité {value}. Résultat attendu : {expected_validity}")
            
            if not expected_validity:
                self.assertIn(expected_error, self.form.capacity.errors)

        # Tester le prix
        price_test_cases = [
            (-0.01, False, "Le prix doit être un nombre non négatif"),
            (0, True, None),
            (10.50, True, None)
        ]

        for value, expected_validity, expected_error in price_test_cases:
            self._prepare_base_form()
            self.form.price.data = value
            self.form.capacity.data = 1  # Ajouter une capacité valide

            validation_result = self.form.validate()
            
            print(f"\nTesting price: {value}")
            print(f"Form data: {self.form.data}")
            print(f"Validation result: {validation_result}")
            print(f"Form errors: {self.form.errors}")
            
            if not validation_result:
                print("Price field errors:", self.form.price.errors)
            
            self.assertEqual(validation_result, expected_validity, 
                             f"Échec pour le prix {value}. Résultat attendu : {expected_validity}")
            
            if not expected_validity:
                self.assertIn(expected_error, self.form.price.errors)

if __name__ == '__main__':
    unittest.main()

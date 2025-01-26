import unittest
from wtforms.validators import ValidationError
from forms import validate_email
from wtforms import Form, StringField

class MockForm(Form):
    email = StringField('Email')

class TestEmailValidation(unittest.TestCase):
    def test_valid_emails(self):
        """Test que des emails valides passent la validation"""
        valid_emails = [
            'user@example.com',
            'user.name@example.co.uk',
            'user+tag@example.org',
            'user123@example-domain.com'
        ]
        
        form = MockForm()
        for email in valid_emails:
            form.email.data = email
            try:
                validate_email(form, form.email)
            except ValidationError:
                self.fail(f"Email valide {email} a échoué à la validation")
    
    def test_invalid_emails(self):
        """Test que des emails invalides échouent à la validation"""
        invalid_emails = [
            '',  # Email vide
            'test.exemple',  # Pas de @
            'test@',  # Pas de domaine
            'test@domaine',  # Pas d'extension
            '@domaine.com',  # Pas de nom
            'test@.com',  # Domaine incomplet
            'test@domaine.',  # Extension manquante
        ]
        
        form = MockForm()
        for email in invalid_emails:
            form.email.data = email
            with self.assertRaises(ValidationError, msg=f"L'email {email} aurait dû échouer"):
                validate_email(form, form.email)

if __name__ == '__main__':
    unittest.main()

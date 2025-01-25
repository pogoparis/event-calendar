import unittest
from app import validate_image_url
from wtforms import Form, StringField
from wtforms.validators import ValidationError

class TestImageUrlValidation(unittest.TestCase):
    def setUp(self):
        class TestForm(Form):
            image_url = StringField('Image URL')

        self.form = TestForm()

    def test_valid_image_urls(self):
        valid_urls = [
            'https://example.com/image.jpg',
            'http://test.com/photo.png',
            'https://website.org/image.gif'
        ]
        
        for url in valid_urls:
            self.form.image_url.data = url
            try:
                validate_image_url(self.form, self.form.image_url)
            except ValidationError:
                self.fail(f"URL {url} should be valid")

    def test_invalid_image_urls(self):
        invalid_urls = [
            'not a url',
            'htp://invalid.com',
            'example.com/image'
        ]
        
        for url in invalid_urls:
            self.form.image_url.data = url
            with self.assertRaises(ValidationError, msg=f"URL {url} should be invalid"):
                validate_image_url(self.form, self.form.image_url)

    def test_empty_url(self):
        self.form.image_url.data = ''
        try:
            validate_image_url(self.form, self.form.image_url)
        except ValidationError:
            self.fail("Empty URL should be allowed")

if __name__ == '__main__':
    unittest.main()

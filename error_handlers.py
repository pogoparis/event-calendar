# Gestion centralisée des erreurs personnalisées

from flask import render_template, request, jsonify
import traceback
import logging

# Configuration du logger
logger = logging.getLogger(__name__)

def register_error_handlers(app):
    """
    Enregistre les gestionnaires d'erreurs personnalisés pour l'application.
    
    :param app: Instance de l'application Flask
    """
    @app.errorhandler(404)
    def not_found_error(error):
        """
        Gestionnaire d'erreur pour les ressources non trouvées (404).
        
        :param error: Objet d'erreur
        :return: Page d'erreur personnalisée ou réponse JSON
        """
        logger.warning(f"Page non trouvée : {request.url}")
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({"error": "Ressource non trouvée", "status": 404}), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def forbidden_error(error):
        """
        Gestionnaire d'erreur pour les accès interdits (403).
        
        :param error: Objet d'erreur
        :return: Page d'erreur personnalisée ou réponse JSON
        """
        logger.warning(f"Accès interdit : {request.url}")
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({"error": "Accès non autorisé", "status": 403}), 403
        return render_template('errors/403.html'), 403

    @app.errorhandler(500)
    def internal_error(error):
        """
        Gestionnaire d'erreur pour les erreurs internes du serveur (500).
        
        :param error: Objet d'erreur
        :return: Page d'erreur personnalisée ou réponse JSON
        """
        logger.error(f"Erreur interne du serveur : {str(error)}")
        logger.error(traceback.format_exc())
        
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({
                "error": "Erreur interne du serveur", 
                "message": str(error),
                "status": 500
            }), 500
        
        return render_template('errors/500.html'), 500

    @app.errorhandler(Exception)
    def unhandled_exception(error):
        """
        Gestionnaire pour toutes les exceptions non gérées.
        
        :param error: Objet d'exception
        :return: Page d'erreur personnalisée ou réponse JSON
        """
        logger.critical(f"Exception non gérée : {str(error)}")
        logger.critical(traceback.format_exc())
        
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({
                "error": "Une erreur inattendue s'est produite", 
                "message": str(error),
                "status": 500
            }), 500
        
        return render_template('errors/unexpected.html', error=str(error)), 500

def log_error(error_type, message, details=None):
    """
    Fonction utilitaire pour logger différents types d'erreurs.
    
    :param error_type: Type d'erreur (warning, error, critical)
    :param message: Message descriptif de l'erreur
    :param details: Détails supplémentaires optionnels
    """
    log_methods = {
        'warning': logger.warning,
        'error': logger.error,
        'critical': logger.critical
    }
    
    log_method = log_methods.get(error_type, logger.info)
    
    if details:
        log_method(f"{message} - Détails : {details}")
    else:
        log_method(message)

class CustomValidationError(Exception):
    """
    Exception personnalisée pour les erreurs de validation.
    """
    def __init__(self, message, errors=None):
        """
        Initialise une erreur de validation personnalisée.
        
        :param message: Message principal de l'erreur
        :param errors: Dictionnaire optionnel des erreurs détaillées
        """
        super().__init__(message)
        self.errors = errors or {}

class DatabaseOperationError(Exception):
    """
    Exception personnalisée pour les erreurs d'opérations de base de données.
    """
    def __init__(self, message, operation=None):
        """
        Initialise une erreur d'opération de base de données.
        
        :param message: Message principal de l'erreur
        :param operation: Type d'opération ayant échoué
        """
        super().__init__(message)
        self.operation = operation

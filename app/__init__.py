# app/__init__.py
from flask import Flask


def create_app():
    """
    Application factory - creates and configures the Flask app.
    This pattern allows proper initialization of extensions and resources.
    """
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')

    # Ensure data directories exist
    import os
    os.makedirs("data", exist_ok=True)
    os.makedirs("data/quarantine", exist_ok=True)

    # Initialize database and load ML model once at startup
    from engine.logger import init_db
    from engine.model_loader import load_model

    with app.app_context():
        init_db()        # Creates SQLite DB + table if not exists
        load_model()     # Loads the .pkl model into memory once

    # Register routes
    from .routes import main
    app.register_blueprint(main)

    # Optional: Add a simple health check
    @app.route('/health')
    def health():
        return {"status": "healthy", "service": "Phishing Shield"}, 200

    return app
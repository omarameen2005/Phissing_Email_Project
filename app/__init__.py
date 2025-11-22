# app/__init__.py
from flask import Flask


def create_app():
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')

    import os
    os.makedirs("data", exist_ok=True)
    os.makedirs("data/quarantine", exist_ok=True)

    from engine.logger import init_db
    from engine.model_loader import load_model

    with app.app_context():
        init_db()        
        load_model()     


    from .routes import main
    app.register_blueprint(main)


    @app.route('/health')
    def health():
        return {"status": "healthy", "service": "Phishing Shield"}, 200

    return app
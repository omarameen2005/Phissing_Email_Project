

from flask import Flask
import os

def create_app():
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')

    os.makedirs("data", exist_ok=True)
    os.makedirs("data/quarantine", exist_ok=True)
    os.makedirs("static/plots", exist_ok=True) 

    from engine.logger import init_db
    from engine.model_loader import load_model
    from model.shap_explain import load_background_data 

    with app.app_context():
        init_db()        
        load_model()     
        load_background_data()  # NEW

    from .routes import main
    app.register_blueprint(main)

    @app.route('/health')
    def health():
        return {"status": "healthy", "service": "Phishing Shield"}, 200

    return app
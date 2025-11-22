from .chain import (
    BaseHandler,
    URLHandler,
    HeaderHandler,
    ModelHandler,
    build_chain
)


from .logger import (
    init_db,
    log_scan,
    get_recent_logs,
    get_stats,
    get_conn
)


from .extractor_url import (
    extract_urls,
    url_features
)

from .model_loader import (
    load_model,
    get_model
)

__version__ = "1.0.0"
__author__ = "Your Name"


try:
    init_db()
except Exception:
    pass  

__all__ = [

    "BaseHandler", "URLHandler", "HeaderHandler", "ModelHandler", "build_chain",
 
    "process_email",
  
    "init_db", "log_scan", "get_recent_logs", "get_stats",
   
    "extract_urls", "url_features",
   
    "load_model", "get_model"
]
import os
from dotenv import load_dotenv

load_dotenv()

SERVICES_DIR = "data_sources/services/"
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
REQUEST_DELAY = 0.5
ENVIRONMENT = os.getenv("ENVIRONMENT", "production")
REPORTS_DIR = "reports"

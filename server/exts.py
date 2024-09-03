from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_cors import CORS
from flask_migrate import Migrate
from flask_apscheduler import APScheduler

login_manager = LoginManager()
db = SQLAlchemy()
scheduler = APScheduler()
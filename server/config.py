from flask import Flask
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData

# ----------------------------
# APP CONFIG
# ----------------------------
app = Flask(__name__)
app.secret_key = b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

# ----------------------------
# DB & MIGRATIONS
# ----------------------------
metadata = MetaData(
    naming_convention={
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)

db = SQLAlchemy(metadata=metadata)
db.init_app(app)   # ✅ only once, this ties db to app

migrate = Migrate(app, db)

# ----------------------------
# SECURITY & API
# ----------------------------
bcrypt = Bcrypt(app)
api = Api(app)

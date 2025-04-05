import os

class Config:
    SECRET_KEY = 'supersecretkey'
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "postgresql://trex:password@localhost/selecteldb")
    SQLALCHEMY_TRACK_MODIFICATIONS = False



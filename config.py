import os

class Config:
    SECRET_KEY = 'secops-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///secops.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

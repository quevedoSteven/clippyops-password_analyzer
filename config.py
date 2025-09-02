import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'military-grade-secret-key-change-in-production'
    API_RATE_LIMIT = 1.5
    MAX_PASSWORD_LENGTH = 128
    MIN_PASSWORD_LENGTH = 4
    BREACH_API_URL = "https://api.pwnedpasswords.com/range/"
    CACHE_TIMEOUT = 3600
    LOG_LEVEL = 'INFO'
    
class DevelopmentConfig(Config):
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
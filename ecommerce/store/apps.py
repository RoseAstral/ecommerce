from django.apps import AppConfig
from .twitter import Tweet


class StoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "store"

    def ready(self): 
        Tweet()

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "secure_file_transfer_web.settings")
application = get_asgi_application()

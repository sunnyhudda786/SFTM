import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "secure_file_transfer_web.settings")
application = get_wsgi_application()

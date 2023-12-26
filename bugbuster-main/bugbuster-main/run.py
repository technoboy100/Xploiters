# Run a server.
import os
#from gevent.pywsgi import WSGIServer
from app import app
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5500))
    app.run(host='0.0.0.0', port=port)
import os.path
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rebuilder.app import app  # noqa: E402


app.config.setdefault('DATABASE_URL', 'sqlite:///rebuilder.db')
app.run(debug=True)

from app import app
from .models import User

@app.route("/")
def index():
    return "Hello world!"

@app.route("/about")
def about():
    return "It's all about me!"
from app import app
from .models import User

@app.route("/")
def index():
    return "Hello Smit!"

@app.route("/about")
def about():
    return "It's all about me!"
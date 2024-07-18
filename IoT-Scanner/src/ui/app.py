from flask import Flask, render_template
from data.storage import get_all_devices

app = Flask(__name__)

@app.route('/')
def index():
    devices = get_all_devices()
    return render_template('index.html', devices=devices)

def start_web_ui():
    app.run(host='0.0.0.0', port=5000)

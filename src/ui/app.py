# app.py

from flask import Flask, render_template, jsonify
import logging
from data.storage import get_all_devices
from device_detection.historical_data_analysis import get_historical_data

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def index():
    try:
        devices = get_all_devices()
        historical_data = get_historical_data()
        return render_template('index.html', devices=devices, historical_data=historical_data)
    except Exception as e:
        logging.error(f"Error rendering index: {e}")
        return jsonify({"error": str(e)}), 500

def start_web_ui():
    app.run(host='0.0.0.0', port=5000, debug=True)

from flask import Flask, render_template, request, jsonify, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import mysql.connector
from mysql.connector import Error
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.secret_key = 'secret_key'

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'forum'
}

socketio = SocketIO(app)

def get_db_connection():
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Fel vid anslutning till MySQL: {e}")
        return None

@app.route('/', methods = ['GET'])
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET, POST'])
def login():
    if request.method == 'POST':
        return

@app.route('/users', methods=['GET'])
def get_users():
    user = request.args.get('username', '')
    return render_template('index.html')

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
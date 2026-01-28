from flask import Flask, render_template, request, jsonify, url_for, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from mysql.connector import Error, connect
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import CSRFProtect
from flask_wtf.csrf import validate_csrf, CSRFError, generate_csrf

app = Flask(__name__)
CORS(app)
app.secret_key = 'secret_key'
csrf = CSRFProtect(app)

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'forum_db'
}

socketio = SocketIO(app)

def get_db_connection():
    try:
        connection = connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Fel vid anslutning till MySQL: {e}")
        return None

@app.route('/', methods = ['GET'])
def index():
    return render_template('index.html')

@app.route('/register', methods = ['GET'])
def get_register():
    return render_template('register.html')

@app.route('/api/get_csrf', methods=['GET'])
def get_csrf():
    token = generate_csrf()
    return jsonify({"csrf_token": token})

@app.route('/api/register', methods = ['POST'])
def register():
    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "Invalid or missing JSON"}), 400

    username = data.get("username")
    password = data.get("password")
    confirmPassword = data.get("confirmPassword")
    name = data.get("name")

    if password != confirmPassword:
        return jsonify({"error": "Passwords must match"}), 400
    
    # Anslut till databasen
    connection = get_db_connection()
    if connection is None:
        return jsonify({"error": "Databasanslutning misslyckades"}), 500
    
    try:
        # Kontrollera om användaren redan är registrerad i databasen
        # Om användaren inte finns så sätt sessionsvariabler och skicka tillbaka en hälsning med användarens namn.
        cursor = connection.cursor(dictionary=True)
        query = "SELECT id FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user:
            return jsonify({"error": "Användarnamnet är redan registrerat"}), 409

        hashed_password = generate_password_hash(password)
        query = """
            INSERT INTO users (username, name, password)
            VALUES (%s, %s, %s)
        """
        cursor.execute(query, (username, name, hashed_password))
        connection.commit()

        query = "SELECT id, username FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({"message": "success"})
    except Error as e:
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "Invalid or missing JSON"}), 400

    username = data.get("username")
    password = data.get("password")
    
    # Anslut till databasen
    connection = get_db_connection()
    if connection is None:
        return jsonify({"error": "Databasanslutning misslyckades"}), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        # Kontrollera om användaren fanns i databasen och lösenordet är korrekt.
        # Om lösenordet är korrekt så sätt sessionsvariabler och skicka tillbaka en hälsning med användarens namn.
        # Om lösenordet inte är korrekt skicka tillbaka ett felmeddelande med http-status 401.
        
        if user and check_password_hash(user['password'], password):
            # Inloggning lyckades - spara användarinfo i session
            session['user_id'] = user['id']
            session['username'] = user['username']
            return jsonify({"message": "success"})
        else:
            # Inloggning misslyckades, skicka http status 401 (Unauthorized)
            return jsonify({"error": "Ogiltigt användarnamn eller lösenord"}), 401
    except Error as e:
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "success"})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
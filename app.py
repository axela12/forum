from flask import Flask, render_template, request, jsonify, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from mysql.connector import Error, connect
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import (
    JWTManager, jwt_required, get_jwt_identity, get_jwt,
    create_access_token, create_refresh_token,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies
)
from datetime import timedelta

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token"
app.config["JWT_REFRESH_COOKIE_NAME"] = "refresh_token"
app.config["JWT_COOKIE_SECURE"] = False # HTTPS only (False for local dev)
app.config["JWT_COOKIE_SAMESITE"] = "Lax" # or "None"
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
app.config["JWT_ALGORITHM"] = "HS256"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

CORS(
    app,
    supports_credentials=True,
    origins=["http://localost:5000"]
)
jwt = JWTManager(app)
socketio = SocketIO(app)

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'forum_db'
}

def get_db_connection():
    try:
        connection = connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Fel vid anslutning till MySQL: {e}")
        return None

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token har gått ut, vänligen logga in igen"}), 401

#index.html
@app.route('/', methods = ['GET'])
def index():
    return render_template('index.html')

#register.html
@app.route('/register', methods = ['GET'])
def register():
    return render_template('register.html')

#apis
#logga in
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Felaktig JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    connection.close()

    if user and check_password_hash(user["password"], password):
        access_token = create_access_token(
            identity=str(user["id"]),
            additional_claims={
                "username": user["username"],
                "name": user["name"]
            }
        )
        refresh_token = create_refresh_token(
            identity=str(user["id"]),
            additional_claims={
                "username": user["username"],
                "name": user["name"]
            }
        )
        response = jsonify({"message": "Inloggad"})
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)
        return response, 200
    else:
        return jsonify({"error": "Ogiltigt användarnamn eller lösenord"}), 401

#registrera
@app.route("/users", methods=["POST"])
def post_user():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Felaktig JSON"}), 400

    name = data.get("name")
    username = data.get("username")
    password = data.get("password")
    confirm_password = data.get("confirm_password")

    if not name or not username or not password or not confirm_password:
        return jsonify({"error": "Alla fält måste fyllas i"}), 400
    
    if password != confirm_password:
        return jsonify({"error": "Lösenorden matchar inte"}), 400

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        return jsonify({"error": "Användarnamnet är upptaget"}), 409

    hashed_password = generate_password_hash(password)
    cursor.execute(
        "INSERT INTO users (username, name, password) VALUES (%s, %s, %s)",
        (username, name, hashed_password)
    )
    connection.commit()
    cursor.close()
    connection.close()

    return jsonify({"message": "Användare skapad"}), 201

#profil
@app.route("/profile", methods=["GET"])
@jwt_required(optional=True)
def profile():
    if get_jwt_identity():
        fetch = request.args.get('fetch', default='')
        if fetch == 'all':
            claims = get_jwt()
            return jsonify({
                "user_id": get_jwt_identity(),
                "username": claims.get('username'),
                "name": claims.get('name')
            }), 200
        return jsonify({"user_id": get_jwt_identity()}), 200
    return jsonify({"error": "Inte inloggad"}), 401

@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT id, username, name FROM users")
    users = cursor.fetchall()

    cursor.close()
    connection.close()

    return jsonify(users)

@app.route("/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        "SELECT id, username, name FROM users WHERE id = %s",
        (user_id,)
    )
    user = cursor.fetchone()

    cursor.close()
    connection.close()

    if not user:
        return jsonify({"error": "Användaren hittades inte"}), 404

    return jsonify(user)

@app.route("/users/<int:id>", methods=["PUT"])
@jwt_required()
def put_user(id):
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Felaktig JSON"}), 400

    name = data.get("name")
    username = data.get("username")
    password = data.get("password")

    if not name or not username or not password:
        return jsonify({"error": "Alla fält måste fyllas i"}), 400

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT id FROM users WHERE id = %s", (id,))
    if not cursor.fetchone():
        return jsonify({"error": "Användaren hittades inte"}), 404

    hashed_password = generate_password_hash(password)
    cursor.execute(
        """
        UPDATE users
        SET username = %s, name = %s, password = %s
        WHERE id = %s
        """,
        (username, name, hashed_password, id)
    )
    connection.commit()

    cursor.close()
    connection.close()

    return jsonify({"message": "Användare uppdaterad"}), 200

@app.route("/logout", methods=["POST"])
@jwt_required(verify_type=False)
def logout():
    response = jsonify({"message": "Utloggad"})
    unset_jwt_cookies(response)
    return response, 200

@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    response = jsonify({"message": "Förnyad access token"})
    set_access_cookies(response, access_token)
    return response

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
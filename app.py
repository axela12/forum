from functools import wraps
from flask import Flask, render_template, request, jsonify, abort
from datetime import timedelta
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from mysql.connector import Error, connect
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import (
    JWTManager, jwt_required, get_jwt_identity, get_jwt, create_access_token
)

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
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

blocklisted_tokens = set()

def get_db_connection():
    try:
        connection = connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Fel vid anslutning till MySQL: {e}")
        return None

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            user_role = claims.get('role', 'user')
            if user_role != required_role:
                abort(403, description="Forbidden: Insufficient privileges")
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.before_request
@jwt_required(optional=True)
def check_revoked_token():
    jti = get_jwt().get('jti')
    if jti in blocklisted_tokens:
        return jsonify({"error": "Token revoked"}), 401

# logga in
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Alla fält måste fyllas i"}), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, username, password, role FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user["password"], password):
            access_token = create_access_token(
                identity=str(user["id"]),
                additional_claims={
                    "username": user["username"],
                    "role": user["role"]
                }
            )
            return jsonify({"access_token": access_token}), 200
        else:
            return jsonify({"error": "Ogiltigt användarnamn eller lösenord"}), 401
        
    except Error as e:
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# logga ut
@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt().get('jti')
    blocklisted_tokens.add(jti)
    return jsonify({"message": "Utloggningen lyckades"}), 200

# profil
@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    return jsonify({'user_id': get_jwt_identity()}), 200

# registrera
@app.route("/users", methods=["POST"])
def post_user():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")

        if not email or not username or not password:
            return jsonify({"error": "Alla fält måste fyllas i"}), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return jsonify({"error": "Användarnamnet är upptaget"}), 409

        hashed_password = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password)
        )
        connection.commit()

        return jsonify({"message": "Användare skapad"}), 201
        
    except Error as e:
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/users", methods=["GET"])
@jwt_required()
def get_users():
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT id, username, email, role FROM users")
        users = cursor.fetchall()

        return jsonify(users)
            
    except Error as e:
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Användaren hittades inte"}), 404

        return jsonify(user)
            
    except Error as e:
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/users/<int:id>", methods=["PUT"])
@jwt_required()
def put_user(id):
    try:
        data = request.get_json()
        email = data.get("email")
        username = data.get("username")
        password = data.get("password")

        if not email or not username or not password:
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
            SET username = %s, email = %s, password = %s
            WHERE id = %s
            """,
            (username, email, hashed_password, id)
        )
        connection.commit()

        return jsonify({"message": "Användare uppdaterad"}), 200
            
    except Error as e:
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/threads", methods=["GET"])
@jwt_required()
def get_threads():
    try:
        limit = request.args.get("limit", default=20, type=int)
        last_post_at = request.args.get("last_post_at")
        last_id = request.args.get("last_id")

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        if not last_post_at or not last_id:
            cursor.execute("""
                SELECT
                    t.id,
                    t.title,
                    t.post_count,
                    t.last_post_at,
                    COALESCE(u.username,'Deleted user') AS username
                FROM threads t
                LEFT JOIN users u ON t.user_id = u.id
                ORDER BY t.last_post_at DESC, t.id DESC
                LIMIT %s
            """, (limit,))
        else:
            cursor.execute("""
                SELECT
                    t.id,
                    t.title,
                    t.post_count,
                    t.last_post_at,
                    COALESCE(u.username,'Deleted user') AS username
                FROM threads t
                LEFT JOIN users u ON t.user_id = u.id
                WHERE (
                    t.last_post_at < %s
                    OR (t.last_post_at = %s AND t.id < %s)
                )
                ORDER BY t.last_post_at DESC, t.id DESC
                LIMIT %s
            """, (last_post_at, last_post_at, last_id, limit))

        threads = cursor.fetchall()

        return jsonify(threads)
    
    except Error as e:
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/threads", methods=["POST"])
@jwt_required()
def post_thread():
    try:
        data = request.get_json()
        title = data.get("title")
        content = data.get("content")
        user_id = data.get("user_id")

        if not title or not content or not user_id:
            return jsonify({"error": "Alla fält måste fyllas i"}), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "INSERT INTO threads (user_id, title) VALUES (%s, %s)",
            (user_id, title)
        )
        connection.commit()

        cursor.execute(
            "SELECT id FROM threads WHERE user_id = %s AND title = %s",
            (user_id, title)
        )

        thread = cursor.fetchone()

        return jsonify({"id": thread["id"]})
    
    except Error as e:
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/threads/<int:thread_id>", methods=["GET"])
@jwt_required()
def get_thread(thread_id):
    try:
        limit = request.args.get("limit", default=20, type=int)
        last_created_at = request.args.get("last_created_at")
        last_id = request.args.get("last_id")

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT t.id, t.title, t.post_count, t.last_post_at,
                   COALESCE(u.username,'Deleted user') AS username
            FROM threads t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.id = %s
        """, (thread_id,))
        thread = cursor.fetchone()

        if not thread:
            return jsonify({"error": "Thread not found"}), 404

        if not last_created_at or not last_id:
            cursor.execute("""
                SELECT p.id, p.content, p.created_at,
                       COALESCE(u.username,'Deleted user') AS username
                FROM posts p
                LEFT JOIN users u ON p.user_id = u.id
                WHERE p.thread_id = %s
                ORDER BY p.created_at ASC, p.id ASC
                LIMIT %s
            """, (thread_id, limit))
        else:
            cursor.execute("""
                SELECT p.id, p.content, p.created_at,
                       COALESCE(u.username,'Deleted user') AS username
                FROM posts p
                LEFT JOIN users u ON p.user_id = u.id
                WHERE p.thread_id = %s
                  AND (p.created_at > %s OR (p.created_at = %s AND p.id > %s))
                ORDER BY p.created_at ASC, p.id ASC
                LIMIT %s
            """, (thread_id, last_created_at, last_created_at, last_id, limit))

        posts = cursor.fetchall()

        return jsonify({
            "thread": thread,
            "posts": posts
        })
    
    except Error as e:
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# index
@app.route('/', methods = ['GET'])
def index():
    return render_template('index.html')

# register
@app.route('/register', methods = ['GET'])
def register():
    return render_template('register.html')

@app.route('/thread/<int:thread_id>', methods = ['GET'])
def forum_thread(thread_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT id, title FROM threads WHERE id = %s", (thread_id,))
        thread = cursor.fetchone()

        if not thread:
            return abort(404, description="Thread not found")
        
        return render_template('thread.html', thread_id = thread["id"], thread_title = thread["title"])
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
from functools import wraps
from flask import Flask, render_template, request, jsonify, abort
from datetime import datetime, timedelta
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from mysql.connector import Error, connect
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import (
    JWTManager, jwt_required, get_jwt_identity, get_jwt,
    verify_jwt_in_request, create_access_token, decode_token
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
socketio = SocketIO(app, cors_allowed_origins="*")

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
                return jsonify({"error": "Forbidden: Insufficient privileges"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.before_request
def check_revoked_token():
    try:
        verify_jwt_in_request(optional=True)
        jwt_data = get_jwt()
        if jwt_data:
            jti = jwt_data.get("jti")
            if jti in blocklisted_tokens:
                return jsonify({"error": "Token revoked"}), 401
    except Exception:
        pass

# logga in
@app.route("/login", methods=["POST"])
def login():
    connection = None
    cursor = None

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
        if connection and connection.is_connected():
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
    connection = None
    cursor = None

    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")

        if not email or not username or not password:
            return jsonify({"error": "Alla fält måste fyllas i"}), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        cursor.execute("SELECT 1 FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return jsonify({"error": "Användarnamnet är upptaget"}), 409
        
        cursor.execute("SELECT 1 FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "E-postaddressen är upptaget"}), 409

        hashed_password = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password)
        )
        user_id = cursor.lastrowid

        connection.commit()

        cursor.execute(
            "SELECT role, created_at FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()

        room = "users"
        socketio.emit('new_user', {
            "id": user_id,
            "username": username,
            "email": email,
            "role": user["role"],
            "created_at": user["created_at"].isoformat()
        }, room=room)

        return jsonify({"message": "Användare skapad"}), 201
        
    except Error as e:
        if connection:
            connection.rollback()
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/users", methods=["GET"])
@role_required("admin")
def get_users():
    connection = None
    cursor = None

    try:
        limit = request.args.get("limit", default=10, type=int)
        last_created_at = request.args.get("last_created_at")
        last_id = request.args.get("last_id")

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        if not last_created_at or not last_id:
            cursor.execute("""
                SELECT
                    id,
                    role,
                    email,
                    created_at,
                    COALESCE(username,'Deleted user') AS username
                FROM users
                ORDER BY created_at DESC, id DESC
                LIMIT %s
            """, (limit,))
        else:
            last_created_at = datetime.fromisoformat(last_created_at)
            cursor.execute("""
                SELECT
                    id,
                    role,
                    email,
                    created_at,
                    COALESCE(username,'Deleted user') AS username
                FROM users
                WHERE (
                    created_at < %s
                    OR (created_at = %s AND id < %s)
                )
                ORDER BY created_at DESC, id DESC
                LIMIT %s
            """, (last_created_at, last_created_at, last_id, limit))
            
        users = cursor.fetchall()

        for user in users:
            if user.get("created_at"):
                user["created_at"] = user["created_at"].isoformat()

        return jsonify(users)

    except Error as e:
        if connection:
            connection.rollback()
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        cursor.execute(
            "SELECT username, role FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Användaren hittades inte"}), 404

        return jsonify(user)
            
    except Error as e:
        if connection:
            connection.rollback()
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/users/<int:id>", methods=["PUT"])
@role_required("admin")
def put_user(id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        cursor.execute("SELECT username, email, password, role FROM users WHERE id = %s", (id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Användaren hittades inte"}), 404
        
        data = request.get_json()
        email = data.get("email", user["email"])
        username = data.get("username", user["username"])
        password = data.get("password", user["password"])
        role = data.get("role", user["role"])

        hashed_password = generate_password_hash(password)
        cursor.execute(
            """
            UPDATE users
            SET username = %s, email = %s, password = %s, role = %s
            WHERE id = %s
            """,
            (username, email, hashed_password, role, id)
        )
        connection.commit()

        return jsonify({"message": "Användare uppdaterad"}), 200
            
    except Error as e:
        if connection:
            connection.rollback()
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/users/<int:id>", methods=["DELETE"])
@role_required("admin")
def delete_user(id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        cursor.execute("SELECT 1 FROM users WHERE id = %s", (id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Användaren hittades inte"}), 404
        
        cursor.execute(
            "DELETE FROM users WHERE id = %s",
            (id,)
        )
        connection.commit()

        return jsonify({"message": "Användare raderad"}), 200
            
    except Error as e:
        if connection:
            connection.rollback()
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/threads", methods=["GET"])
def get_threads():
    connection = None
    cursor = None

    try:
        limit = request.args.get("limit", default=10, type=int)
        last_post_at = request.args.get("last_post_at")
        last_id = request.args.get("last_id")

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        if not last_post_at or not last_id:
            cursor.execute("""
                SELECT
                    t.id,
                    t.title,
                    t.post_count,
                    t.last_post_id,
                    t.last_post_at,
                    COALESCE(u.username,'Deleted user') AS username
                FROM threads t
                LEFT JOIN users u ON t.user_id = u.id
                ORDER BY t.last_post_at DESC, t.id DESC
                LIMIT %s
            """, (limit,))
        else:
            last_post_at = datetime.fromisoformat(last_post_at)
            cursor.execute("""
                SELECT
                    t.id,
                    t.title,
                    t.post_count,
                    t.last_post_id,
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

        for thread in threads:
            if thread.get("last_post_at"):
                thread["last_post_at"] = thread["last_post_at"].isoformat()

        return jsonify(threads)
    
    except Error as e:
        if connection:
            connection.rollback()
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/threads", methods=["POST"])
@jwt_required()
def post_thread():
    connection = None
    cursor = None

    try:
        data = request.get_json()
        title = data.get("title")
        content = data.get("content")
        user_id = get_jwt_identity()

        if not title or not content:
            return jsonify({"error": "Alla fält måste fyllas i"}), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        cursor.execute(
            "INSERT INTO threads (user_id, title) VALUES (%s, %s)",
            (user_id, title)
        )
        thread_id = cursor.lastrowid

        cursor.execute(
            "INSERT INTO posts (thread_id, user_id, content) VALUES (%s, %s, %s)",
            (thread_id, user_id, content)
        )
        post_id = cursor.lastrowid

        cursor.execute(
            "SELECT id, created_at FROM posts WHERE id = %s",
            (post_id,)
        )
        latest_post = cursor.fetchone()

        cursor.execute(
            """UPDATE threads
               SET last_post_id = %s,
                    last_post_at = %s,
                    post_count = post_count + 1
               WHERE id = %s""",
            (latest_post["id"], latest_post["created_at"], thread_id)
        )

        cursor.execute("""
            SELECT t.id, t.title, t.post_count, t.last_post_at,
                COALESCE(u.username,'Deleted user') AS username
            FROM threads t
            LEFT JOIN users u ON t.user_id = u.id
            WHERE t.id = %s
        """, (thread_id,))
        thread = cursor.fetchone()

        connection.commit()

        room = "threads"
        socketio.emit('new_thread', {
            "id": thread["id"],
            "title": thread["title"],
            "username": thread["username"],
            "post_count": thread["post_count"],
            "last_post_at": thread["last_post_at"].isoformat()
        }, room=room)

        return jsonify({"id": thread_id}), 201

    except Error as e:
        if connection:
            connection.rollback()
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/threads/<int:thread_id>", methods=["GET"])
def get_thread(thread_id):
    connection = None
    cursor = None

    try:
        limit = request.args.get("limit", default=10, type=int)
        last_created_at = request.args.get("last_created_at")
        last_id = request.args.get("last_id")

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        cursor.execute("""
            SELECT 1 FROM threads WHERE id = %s LIMIT 1
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
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT %s
            """, (thread_id, limit))
        else:
            last_created_at = datetime.fromisoformat(last_created_at)
            cursor.execute("""
                SELECT p.id, p.content, p.created_at,
                    COALESCE(u.username,'Deleted user') AS username
                FROM posts p
                LEFT JOIN users u ON p.user_id = u.id
                WHERE p.thread_id = %s
                    AND (p.created_at < %s OR (p.created_at = %s AND p.id < %s))
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT %s
            """, (thread_id, last_created_at, last_created_at, last_id, limit))

        posts = cursor.fetchall()

        for post in posts:
            if post.get("created_at"):
                post["created_at"] = post["created_at"].isoformat()

        return jsonify(posts)
    
    except Error as e:
        if connection:
            connection.rollback()
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@app.route("/threads/<int:thread_id>", methods=["POST"])
@jwt_required()
def post_post(thread_id):
    connection = None
    cursor = None

    try:
        data = request.get_json()
        content = data.get("content")
        user_id = get_jwt_identity()

        if not content:
            return jsonify({"error": "Alla fält måste fyllas i"}), 400

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        cursor.execute(
            "INSERT INTO posts (thread_id, user_id, content) VALUES (%s, %s, %s)",
            (thread_id, user_id, content)
        )
        post_id = cursor.lastrowid

        cursor.execute(
            "SELECT id, created_at FROM posts WHERE id = %s",
            (post_id,)
        )
        latest_post = cursor.fetchone()

        cursor.execute(
            """UPDATE threads
               SET last_post_id = %s,
                    last_post_at = %s,
                    post_count = post_count + 1
               WHERE id = %s""",
            (latest_post["id"], latest_post["created_at"], thread_id)
        )

        cursor.execute(
            "SELECT post_count, last_post_id, last_post_at FROM threads WHERE id = %s",
            (thread_id,)
        )
        updated_thread = cursor.fetchone()

        cursor.execute("""
            SELECT p.content, p.created_at,
                COALESCE(u.username,'Deleted user') AS username
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.id = %s
        """, (post_id,))
        post = cursor.fetchone()

        connection.commit()

        room = f"thread_{thread_id}"
        socketio.emit('new_post', {
            "id": post_id,
            "thread_id": thread_id,
            "post_count": updated_thread["post_count"],
            "username": post["username"],
            "content": post["content"],
            "created_at": post["created_at"].isoformat()
        }, room=room)

        room = "threads"
        socketio.emit('new_post', {
            "id": thread_id,
            "post_count": updated_thread["post_count"],
            "last_post_id": updated_thread["last_post_id"],
            "last_post_at": updated_thread["last_post_at"].isoformat()
        }, room=room)

        return jsonify({"post_id": post_id}), 201

    except Error as e:
        if connection:
            connection.rollback()
        print(f"Databasfel: {e}")
        return jsonify({"error": "Databasfel inträffade"}), 500

    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

@socketio.on('join_room')
def handle_join_room(data):
    room = data.get('room')
    if not room:
        emit("error", {"error": "Rum saknas"})
        return

    join_room(room)
    emit("joined_room", {"room": room})

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
    connection = None
    cursor = None
    
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT title FROM threads WHERE id = %s", (thread_id,))
        thread = cursor.fetchone()

        if not thread:
            return abort(404, description="Thread not found")
        
        return render_template('thread.html', thread_title = thread["title"])
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# admin panel
@app.route('/admin', methods = ['GET'])
def admin_panel():
    return render_template('users.html')

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
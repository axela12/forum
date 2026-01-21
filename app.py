from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app)

@app.route('/')
def index():    
    return render_template('login.html')

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
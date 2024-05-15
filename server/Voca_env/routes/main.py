import os
import secrets
from flask import Flask, request, jsonify, session, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from dotenv import load_dotenv
import jwt
import logging
from datetime import datetime
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from config import login_key, user_id_key, group_id_key, app_config_key, flask_app_key
from datetime import datetime, timedelta


load_dotenv()

app = Flask(__name__, static_folder="../../../build", static_url_path="")
socketio = SocketIO(app, cors_allowed_origins=["http://localhost:3000"])
CORS(app, resources={r"/*": {"origins": ["http://localhost:3000"]}})
app.secret_key = flask_app_key
print("app.secret_key", app.secret_key)


@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.add(
        "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"
    )
    print("reponse:", response)
    return response


@socketio.on_error()
def handle_socket_error(e):
    print(f"Socket error: {str(e)}")


@socketio.on_error_default
def default_error_handler(e):
    print(f"Socket error: {str(e)}")


@socketio.on("frontend_to_backend")
def handle_frontend_message(message):
    print("Received message from frontend:", message)


@socketio.on("connect")
def handle_connect():
    emit("backend_to_frontend", "Hello from the backend")


logging.basicConfig(
    level=logging.DEBUG,
    filename="app.log",
    format="%(asctime)s %(levelname)s:%(message)s",
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    os.environ.get("DATABASE_URL")
    or "postgresql://postgres:Talintiar123@localhost:5432/userdata"
)

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

print("SQLALCHEMY_DATABASE_URI", app.config["SQLALCHEMY_DATABASE_URI"])

print("DATABASE_URL", os.environ.get("DATABASE_URL"))

app.config["app_config_key"] = app_config_key

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    __tablename__ = "userdata"  # this specifies the name of the table in the database

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    birthdate = db.Column(db.Date)


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("userdata.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    group_id = db.Column(db.String(20), nullable=False)
    user = db.relationship("User", backref=db.backref("messages", lazy=True))


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    hashed_password = generate_password_hash(data["password"], method="pbkdf2:sha1")

    new_user = User(
        name=data["name"],
        email=data["email"],
        username=data["username"],
        password=hashed_password,
        birthdate=data["birthdate"],
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        if "unique" in str(e).lower():
            return jsonify({"message": "Username or email already exists!"}), 400
        print(e)
        return jsonify({"message": "Internal server error!"}), 500
    finally:
        db.session.close()


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user_name_or_email = data.get("username") or data.get("email")
    password = data.get("password")
    name = data.get("name")

    user = User.query.filter(
        (User.username == user_name_or_email) | (User.email == user_name_or_email)
    ).first()

    if not user:
        return jsonify({"error": "User not found!"}), 404
    if check_password_hash(user.password, password):
        login_token = jwt.encode({"user_id": user.id}, login_key, algorithm="HS256")
        user_token = generate_user_token(login_token)
        group_token = generate_group_token(login_token)
        user.id = get_current_user_id(user_token)
        group_id = get_current_group_id(login_token)
        print("login_token in login func: ", login_token)
        print("user_token in login func", user_token)
        print("user id in login func", user.id)
        print("group_token in login func", group_token)
        print("group_id", group_id)
        return (
            jsonify(
                {
                    "login_token": login_token,
                    "user_token": user_token,
                    "group_token": group_token,
                    "user_id": user.id,
                    "group_id": group_id,
                    "email": user.email,
                    "username": user.username,
                    "name": user.name,
                }
            ),
            200,
        )
    else:
        return jsonify({"error": "Incorrect password!"}), 401


def validate_name(name):
    if len(name) < 3:
        return "Name must be at least 3 characters long."
    return ""


import re


def validate_username(username):
    if len(username) < 3:
        return "Username must be at least 3 characters long."

    letter_count = len(re.findall(r"[a-zA-Z]", username))
    if letter_count < 3:
        return "Username must contain at least 3 letters."

    return ""


def validate_email(email):
    valid_domains = ["gmail.com", "yahoo.com", "outlook.com"]  # Add more as needed
    if "@" not in email or "." not in email:
        return "Email must contain '@' and a dot."

    domain = email.split("@")[1]
    if domain not in valid_domains:
        return "Email domain is not valid."

    return ""


def validate_password(password):
    if len(password) < 10:
        return "Password must be at least 10 characters long."

    if not re.search(r"\d", password):
        return "Password must include at least one number."

    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."

    if not re.search(r"[!?]", password):
        return "Password must include either '!' or '?'."

    return ""


def generate_user_token(login_token):
    if login_token:
        try:
            print("login_token: ", login_token)
            decoded_login_token = jwt.decode(
                login_token, login_key, algorithms=["HS256"]
            )
            user_id = decoded_login_token.get("user_id")

            if user_id:
                payload = {
                    "user_id": user_id,
                    "exp": datetime.utcnow() + timedelta(days=7),
                }
                user_token = jwt.encode(payload, user_id_key, algorithm="HS256")
                print("user_token: gen_u_tok ", user_token)

                return user_token
            else:
                return None
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    else:
        return None


def generate_group_token(login_token):
    if login_token:
        try:
            print("login_token in group token func: ", login_token)
            decoded_login_token = jwt.decode(
                login_token, login_key, algorithms=["HS256"]
            )
            group_id = decoded_login_token.get("group_id")

            if group_id:
                payload = {
                    "group_id": group_id,
                    "exp": datetime.utcnow() + timedelta(days=7),
                }
                group_token = jwt.encode(payload, group_id_key, algorithm="HS256")
                print("group_token", group_token)

                return group_token
            else:
                return None
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    else:
        return None


def get_current_user_id(user_token):
    # user_token = request.headers.get("Authorization")
    print("user_token: get_cur_tok", user_token)
    if user_token:
        try:
            data = jwt.decode(user_token, user_id_key, algorithms=["HS256"])
            print("data: ", data)
            print("user_id_key: ", user_id_key)
            return data.get("user_id")
        except jwt.ExpiredSignatureError:
            print("Expired Token")
        except jwt.InvalidTokenError:
            print("Invalid Token")

    return None


def get_current_group_id(group_token):
    print("group token info: get_cur_grp", group_token)
    print("group_id_key: ", group_id_key)

    if group_token:
        try:
            data = jwt.decode(group_token, group_id_key, algorithms=["HS256"])
            print("group_data", data)
            return data.get("group_id")
        except jwt.ExpiredSignatureError:
            print("Expired Token")
        except jwt.InvalidTokenError:
            print("Invalid Token")
    else:
        return None


@app.route("/edit", methods=["POST"])
def edit_profile():
    data = request.json
    print("Received data:", data)

    errors = {
        "name": validate_name(data.get("name")),
        "username": validate_username(data.get("username")),
        "email": validate_email(data.get("email")),
        "password": validate_password(data.get("password")),
    }

    if any(errors.values()):
        return jsonify({"error": "Validation failed", "details": errors}), 400

    try:
        user_id = get_current_user_id()
        print("user_id", user_id)

        if not user_id:
            return jsonify({"error": "User ID is missing"}), 400

        user = db.session.get(User, user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404

        user.name = data.get("name")
        user.username = data.get("username")
        user.email = data.get("email")
        if data.get("password"):
            user.password = generate_password_hash(
                data["password"], method="pbkdf2:sha256"
            )

        db.session.commit()

        return (
            jsonify(
                {
                    "name": user.name,
                    "username": user.username,
                    "email": user.email,
                }
            ),
            200,
        )

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error occurred in /edit route: {e}", exc_info=True)
        return jsonify({"error": "An error occurred"}), 500


def decode_user_token(token):
    try:
        data = jwt.decode(token, user_id_key, algorithms=["HS256"])
        return data.get("user_id")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def decode_group_token(token):
    try:
        data = jwt.decode(token, group_id_key, algorithms=["HS256"])
        return data.get("group_id")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


@app.route("/messages/send", methods=["POST"])
def send_message():
    data = request.json
    user_token = data.get("user_token")
    group_token = data.get("group_token")
    print("Request data:", data)
    print("user_token", user_token)
    print("group_token", group_token)
    text = data.get("text")

    user_id = decode_user_token(user_token)
    group_id = decode_group_token(group_token)

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401
    if not group_id:
        return jsonify({"error": "Group ID not found"}), 401
    message = Message(user_id=user_id, group_id=group_id, text=text)
    print("Message:", message)

    try:
        db.session.add(message)
        db.session.commit()
        return jsonify({"message": "Message sent successfully"}), 201
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error occurred in /messages/send route: {e}", exc_info=True)
        return jsonify({"error": "Failed to send message"}), 500


@app.route("/messages", methods=["GET"])
def get_messages():
    user_id = get_current_user_id()
    group_id = get_current_group_id
    print("User ID: /messages", user_id)
    print("Group ID: /messages", group_id)

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    latest_message = (
        Message.query.join(User)
        .filter(Message.user_id == user_id, Message.group_id == group_id)
        .order_by(Message.timestamp.desc())
        .first()
    )

    print("Latest Message:", latest_message)

    if latest_message:
        message_data = {
            "id": latest_message.id,
            "user_id": latest_message.user_id,
            "username": latest_message.user.username,
            "text": latest_message.text,
            "group_id": latest_message.group_id,
            "timestamp": latest_message.timestamp,
        }
        return jsonify(message_data), 200
    else:
        return jsonify({"message": "No messages found"}), 200


@app.route("/messages/all", methods=["GET"])
def get_all_messages():
    user_token = request.headers.get("Authorization")
    group_token = request.headers.get("Group-Authorization")

    user_id = decode_user_token(user_token)
    group_id = decode_group_token(group_token)

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    messages = Message.query.join(User).order_by(Message.timestamp.asc()).all()
    print("Messages:", messages)

    message_data = []
    for message in messages:
        message_data.append(
            {
                "id": message.id,
                "user_id": message.user_id,
                "username": message.user.username,
                "text": message.text,
                "timestamp": message.timestamp,
                "group_id": message.group_id == group_id,
                "is_current_user": message.user_id == user_id,
            }
        )

    return jsonify(message_data), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)

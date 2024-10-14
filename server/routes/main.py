import os
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask import send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from dotenv import load_dotenv, find_dotenv
import jwt
import logging
from datetime import datetime
from flask_socketio import SocketIO, emit
from flask_cors import CORS, cross_origin
from .token_keys_list import (
    login_key,
    user_id_key,
    group_id_key,
    app_config_key,
    flask_app_key,
)
from datetime import datetime, timedelta

load_dotenv()
app = Flask(__name__, static_folder="../../client/build/static", static_url_path="/static")
print("app", app)
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

socketio = SocketIO(app)

db = SQLAlchemy(app)
print("db", db)
migrate = Migrate(app, db)
print("migrate", migrate)

DATABASE_URL = os.environ.get("DATABASE_URL")
print("DATABASE_URL: ", DATABASE_URL)
DB_USER = os.environ.get("DB_USER")
print("DB_USER: ", DB_USER)
DB_PASSWORD = os.environ.get("DB_PASSWORD")
print("DB_PASSWORD: ", DB_PASSWORD)

CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = flask_app_key
print("app.secret_key", app.secret_key)


@app.after_request
def after_request(response):
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

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

print("SQLALCHEMY_DATABASE_URI", app.config["SQLALCHEMY_DATABASE_URI"])

print("DATABASE_URL", os.environ.get("DATABASE_URL"))
app.config["app_config_key"] = app_config_key


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
    group_room_number = db.Column(db.String(20), nullable=False)
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

    user = User.query.filter(
        (User.username == user_name_or_email) | (User.email == user_name_or_email)
    ).first()

    if not user:
        return jsonify({"error": "User not found!"}), 404
    if check_password_hash(user.password, password):
        login_token = jwt.encode({"user_id": user.id}, login_key, algorithm="HS256")
        user_token = generate_user_token(login_token)
        user.id = get_current_user_id(user_token)
        print("login_token in login func: ", login_token)
        print("user_token in login func", user_token)
        print("user id in login func", user.id)
        return (
            jsonify(
                {
                    "login_token": login_token,
                    "user_token": user_token,
                    "user_id": user.id,
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
    if not login_token:
        return None

    try:
        print("login_token: ", login_token)
        decoded_login_token = jwt.decode(login_token, login_key, algorithms=["HS256"])
        user_id = decoded_login_token.get("user_id")

        if not user_id:
            return None

        payload = {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(days=7),
        }
        user_token = jwt.encode(payload, user_id_key, algorithm="HS256")
        print("user_token: gen_u_tok ", user_token)

        return user_token
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def generate_group_token(group_room_number):
    if group_room_number:
        try:
            print("login_token in group token func: ", group_room_number)
            print("GROUP_ID:", group_room_number)
            if group_room_number:
                payload = {
                    "group_id": group_room_number,
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


@app.route("/messages/send", methods=["POST"])
def send_message():
    try:
        data = request.json
        print("Request data:", data)

        if not data:
            return jsonify({"error": "Missing request data"}), 400

        user_token = data.get("user_token")
        group_room_number = data.get("group_room_number")
        print("group_room_number msg/send", group_room_number)
        text = data.get("text")

        print("User token:", user_token)

        if not user_token:
            return jsonify({"error": "Missing user token"}), 400

        try:
            decoded_token = jwt.decode(user_token, user_id_key, algorithms=["HS256"])
            print("Decoded token payload:", decoded_token)
        except jwt.InvalidTokenError as e:
            print("Invalid token:", str(e))
            return jsonify({"error": "Invalid token"}), 401

        user_id = get_current_user_id(user_token)
        print("user_id msg/send: ", user_id)

        if not user_id:
            return jsonify({"error": "Authentication required"}), 401

        message = Message(
            user_id=user_id, group_room_number=group_room_number, text=text
        )
        print("Message:", message)
        db.session.add(message)
        db.session.commit()
        return jsonify({"message": "Message sent successfully"}), 201
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error occurred in /messages/send route: {e}", exc_info=True)
        return jsonify({"error": "Failed to send message"}), 500


@app.route("/messages", methods=["GET"])
def get_messages():
    user_token = request.args.get("user_token")
    group_room_number = request.args.get("group_room_number")
    user_id = get_current_user_id(user_token)
    print("User ID: /messages", user_id)
    print("group_room_number: /messages", group_room_number)

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    message = (
        Message.query.join(User)
        .filter(
            Message.user_id == user_id, Message.group_room_number == group_room_number
        )
        .order_by(Message.timestamp.desc())
        .first()
    )

    print("Latest Message:", message)

    if message:
        message_data = {
            "id": message.id,
            "user_id": message.user_id,
            "username": message.user.username,
            "text": message.text,
            "group_room_number": message.group_room_number,
            "timestamp": message.timestamp,
            "is_current_user": message.user_id == user_id,
        }
        return jsonify(message_data), 200
    else:
        return jsonify({"message": "No messages found"}), 200


@app.route("/search", methods=["GET"])
def filter_search_terms():
    user_token = request.headers.get("Authorization")
    group_room_number = request.args.get("group_room_number")
    user_token_only = str(user_token.replace("Bearer", "")).strip()
    print("user_token_only: ", user_token_only)
    if user_token_only:
        print("searchTerm groupRoomNumber: ", group_room_number)
        search_term = request.args.get("term")
        print("search_term: ", search_term)

        search_Term_Results = (
            (
                Message.query.filter(
                    Message.group_room_number == group_room_number,
                    Message.text.ilike(f"%{search_term}%"),
                )
            )
            .order_by(Message.timestamp.desc())
            .all()
        )

        print("search_Term_Results: ", search_Term_Results)

        if search_Term_Results:
            search_Term_Results_Data = [
                {
                    "id": result.id,
                    "group_room_number": result.group_room_number,
                    "text": result.text,
                    "timestamp": result.timestamp,
                }
                for result in search_Term_Results
            ]

            return jsonify(search_Term_Results_Data), 200
        else:
            return jsonify({"search_term_results": "no results found"}), 200


@app.route("/messages/all", methods=["GET"])
def get_all_messages():
    user_token = request.headers.get("Authorization")
    if user_token:
        user_token = user_token.replace("Bearer ", "")
    group_room_number = request.args.get("group_room_number")
    print("user_token msg/all: ", user_token),
    print("group_room_number msg/all: ", group_room_number)
    user_id = get_current_user_id(user_token)
    print("user_id msg/all: ", user_id)

    if not user_id:
        return jsonify({"error": "Authentication required"}), 401

    if group_room_number:
        messages = (
            Message.query.join(User)
            .filter(Message.group_room_number == group_room_number)
            .order_by(Message.timestamp.asc())
            .all()
        )
    else:
        messages = Message.query.join(User).order_by(Message.timestamp.asc()).all()
    print("group_room_number msg/all: ", group_room_number)

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
                "group_room_number": message.group_room_number,
                "is_current_user": message.user_id == user_id,
            }
        )
    print("message_data msg/all", message_data)
    return jsonify(message_data), 200


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    print("OS.path", os.path)
    find_dir = (app.root_path, "..", "..", "client", "build")
    print("find_dir", find_dir)
    build_dir = os.path.abspath(os.path.join(app.root_path, "..", "..", "client", "build"))
    print("Build_dir", build_dir)
    doesFilePathExist = os.path.exists(os.path.abspath(os.path.join(build_dir, path)))
    print("doesFilePathExist", doesFilePathExist)

    if path != "" and doesFilePathExist:
        return send_from_directory(build_dir, path)
    else:
        try:
            return send_from_directory(build_dir, "index.html")
        except Exception as e:
            return f"An error occurred: {str(e)}", 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=os.environ.get("PORT"))

import os
import secrets
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_migrate import Migrate
from dotenv import load_dotenv
import jwt
import logging

load_dotenv()

app = Flask(__name__, static_folder="../../../build", static_url_path="")
CORS(app, origins=["http://localhost:3000"])

logging.basicConfig(
    level=logging.DEBUG,
    filename="app.log",
    format="%(asctime)s %(levelname)s:%(message)s",
)

SECRET_KEY = secrets.token_hex(16)
print(SECRET_KEY)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    os.environ.get("DATABASE_URL")
    or "postgresql://postgres:Talintiar123@localhost:5432/userdata"
)

print("SQLALCHEMY_DATABASE_URI", app.config["SQLALCHEMY_DATABASE_URI"])

print("DATABASE_URL", os.environ.get("DATABASE_URL"))

app.config["SECRET_KEY"] = SECRET_KEY

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
    token = jwt.encode({"user_id": user.id}, "your_secret_key", algorithm="HS256")
    print("token", token)
    if check_password_hash(user.password, password):
        return (
            jsonify(
                {
                    "token": token,
                    "id": user.id,
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
    return None


import re


def validate_username(username):
    if len(username) < 3:
        return "Username must be at least 3 characters long."

    letter_count = len(re.findall(r"[a-zA-Z]", username))
    if letter_count < 3:
        return "Username must contain at least 3 letters."

    return None


def validate_email(email):
    valid_domains = ["gmail.com", "yahoo.com", "outlook.com"]  # Add more as needed
    if "@" not in email or "." not in email:
        return "Email must contain '@' and a dot."

    domain = email.split("@")[1]
    if domain not in valid_domains:
        return "Email domain is not valid."

    return None


def validate_password(password):
    if len(password) < 10:
        return "Password must be at least 10 characters long."

    if not re.search(r"\d", password):
        return "Password must include at least one number."

    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."

    if not re.search(r"[!?]", password):
        return "Password must include either '!' or '?'."

    return None


def get_current_user_id():
    token = request.headers.get("Authorization")
    if len(token) > 0:
        prefix = "Bearer"
        if token.startswith(prefix):
            token = token[len(prefix) :]  # Remove "Bearer " prefix
            token = token.strip()
        try:
            # Decode the token
            data = jwt.decode(token, "your_secret_key", algorithms=["HS256"])
            return data.get(
                "user_id"
            )  # Use .get to avoid KeyError if "user_id" is missing
        except jwt.ExpiredSignatureError:
            # Handle expired token
            return None
        except jwt.InvalidTokenError:
            # Handle invalid token
            return None
    else:
        # Handle case where no token is provided
        return None


@app.route("/edit", methods=["POST"])
def edit_profile():
    data = request.json
    print("Received data:", data)

    name_error = validate_name(data.get("name"))
    username_error = validate_username(data.get("username"))
    email_error = validate_email(data.get("email"))
    password_error = validate_password(data.get("password"))

    if any([name_error, username_error, email_error, password_error]):
        errors = {
            "name": name_error,
            "username": username_error,
            "email": email_error,
            "password": password_error,
        }
        return jsonify({"error": "Validation failed", "details": errors}), 400

    try:
        user_id = get_current_user_id()
        print("user_id", user_id)

        # Ensure user_id is not None before proceeding
        if not user_id:
            return jsonify({"error": "User ID is missing"}), 400

        user = db.session.get(User, user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Update user attributes
        user.name = data.get("name")
        user.username = data.get("username")
        user.email = data.get("email")
        if data.get("password"):
            user.password = generate_password_hash(
                data["password"], method="pbkdf2:sha256"
            )

        db.session.commit()

        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error occurred in /edit route: {e}", exc_info=True)
        return jsonify({"error": "An error occurred"}), 500


if __name__ == "__main__":
    app.run(debug=True)

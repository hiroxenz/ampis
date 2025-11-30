import os
import bcrypt
import uuid
import datetime
from functools import wraps

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import jwt
from pymongo import MongoClient

app = Flask(__name__)

MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_SECRET = os.getenv("ADMIN_SECRET")

client = MongoClient(MONGO_URI)
db = client["backend_api"]

users = db["users"]
private_keys = db["private_keys"]
api_keys = db["api_keys"]

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100/minute"]
)

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("x-admin-token")
        if token != ADMIN_SECRET:
            return jsonify({"error": "Unauthorized admin"}), 403
        return f(*args, **kwargs)
    return wrapper

def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("authorization")
        if not token:
            return jsonify({"error": "Missing Authorization"}), 401
        try:
            user = jwt.decode(token.replace("Bearer ", ""), JWT_SECRET, algorithms=["HS256"])
            request.user = user
        except:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return wrapper

def api_key_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = request.headers.get("x-api-key")
        if not key:
            return jsonify({"error": "Missing API Key"}), 401
        hashed = bcrypt.hashpw(key.encode(), bcrypt.gensalt()).decode()
        found = api_keys.find_one()
        match = False
        for k in api_keys.find():
            if bcrypt.checkpw(key.encode(), k["key"].encode()):
                match = True
                request.api_user = k["user_id"]
                break
        if not match:
            return jsonify({"error": "Invalid API Key"}), 401
        return f(*args, **kwargs)
    return wrapper


@app.route("/api/v1/admin/create-private-key", methods=["POST"])
@admin_required
def admin_create_private_key():
    pk = str(uuid.uuid4())
    private_keys.insert_one({"private_key": pk, "used": False})
    return jsonify({"private_key": pk})


@app.route("/api/v1/auth/register", methods=["POST"])
def register_user():
    data = request.json
    private_key = data.get("private_key")
    if not private_key:
        return jsonify({"error": "Missing private_key"}), 400

    pk = private_keys.find_one({"private_key": private_key, "used": False})
    if not pk:
        return jsonify({"error": "Invalid or used private key"}), 400

    username = data.get("username")
    password = data.get("password")

    if users.find_one({"username": username}):
        return jsonify({"error": "User exists"}), 400

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    user_id = users.insert_one({
        "username": username,
        "password": hashed_pw
    }).inserted_id

    private_keys.update_one({"private_key": private_key}, {"$set": {"used": True, "user_id": str(user_id)}})

    return jsonify({"message": "Registered"})


@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = users.find_one({"username": username})
    if not user:
        return jsonify({"error": "User not found"}), 400

    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Wrong password"}), 400

    token = jwt.encode({
        "user_id": str(user["_id"]),
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }, JWT_SECRET, algorithm="HS256")

    return jsonify({"token": token})


@app.route("/api/v1/user/new-api-key", methods=["POST"])
@auth_required
def new_api_key():
    user_id = request.user["user_id"]
    new_key = str(uuid.uuid4())
    hashed = bcrypt.hashpw(new_key.encode(), bcrypt.gensalt()).decode()

    api_keys.insert_one({
        "user_id": user_id,
        "key": hashed,
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"api_key": new_key})


@app.route("/api/v1/user/api-keys", methods=["GET"])
@auth_required
def list_api_keys():
    user_id = request.user["user_id"]
    keys = list(api_keys.find({"user_id": user_id}, {"key": 0}))
    for k in keys:
        k["_id"] = str(k["_id"])
    return jsonify(keys)


@app.route("/api/v1/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    data = []
    for u in users.find():
        data.append({
            "id": str(u["_id"]),
            "username": u["username"]
        })
    return jsonify(data)


@app.route("/api/v1/models", methods=["GET"])
@api_key_required
def models():
    return jsonify({
        "object": "list",
        "data": [
            {"id": "gpt-4o", "object": "model"},
            {"id": "gpt-4.1-mini", "object": "model"}
        ]
    })


@app.route("/api/v1/chat/completions", methods=["POST"])
@api_key_required
def chat_completions():
    data = request.json
    messages = data.get("messages", [])
    last_msg = messages[-1]["content"] if messages else ""
    return jsonify({
        "id": f"chatcmpl-{uuid.uuid4()}",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": f"Echo: {last_msg}"},
                "finish_reason": "stop"
            }
        ]
    })


@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "Backend Flask API running"})


def handler(event, context):
    return app(event, context)


if __name__ == "__main__":
    app.run(debug=True)

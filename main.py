from flask import Flask, make_response, jsonify, request, session
from flask_cors import CORS, cross_origin
from functools import wraps
import datetime
import mariadb
import atexit
import bcrypt

from config import env

app = Flask(__name__)
app.secret_key = env["FLASK_SECRET_KEY"]

cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

try:
    conn = mariadb.connect(
        user=env["SQL_USERNAME"],
        password=env["SQL_PASSWORD"],
        host=env["SQL_HOST"],
        port=3306,
        database="TheSkets",
        autocommit=True
    )
except mariadb.Error as e:
    print(e)

"""
Serverside Functions
"""


def close_connections():
    conn.close()
    print("Closed Connection")


"""
Middleware
"""


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "logged_in" not in session or session["logged_in"] == False:
            # Redirect to Login page here
            return make_response("Unauthorized", 401)
        return f(*args, **kwargs)

    return decorated


"""
Private API Routes
"""


@app.route("/v1/private/sign_in", methods=["POST"])
@cross_origin(supports_credentials=True)
def sign_in():
    data = request.get_json()

    if data["password"] is None or data["username"] is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid Password or Username"}), 400)

    username = data["username"]
    password = data["password"]

    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE username = %s", (username,))
    row = c.fetchall()

    if len(row) < 1:
        return make_response(jsonify({"status": "failure", "message": "Account does not exist"}), 400)

    bcrypt.gensalt()
    hashed = password.encode("utf-8")
    real = row[0][2].encode("utf-8")

    if bcrypt.checkpw(hashed, real):
        session["logged_in"] = True
        session["profile"] = {
            "name": username,
            "email": row[0][3],
            "pfp_url": row[0][6],
            "registration_date": row[0][5]
        }

        return jsonify({"status": "success", "session": session["profile"]})
    else:
        return make_response(jsonify({"status": "failure", "message": "Invalid Password or Username"}), 400)


@app.route("/v1/private/sign_up", methods=["POST"])
@cross_origin(supports_credentials=True)
def sign_up():
    data = request.get_json()

    if data["password"] is None or len(data["password"]) < 5:
        return make_response("Invalid Request (Password)", 400)

    if data["username"] is None or len(data["username"]) < 3:
        return make_response("Invalid Request (Username)", 400)

    if data["email"] is None or "@" not in data["email"]:
        return make_response("Invalid Request (Email)", 400)

    username = data["username"]
    password = data["password"]
    email = data["email"].lower().strip()

    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
    rows = c.fetchall()

    if len(rows) > 0:
        if rows[0][1] == username:
            return make_response(
                jsonify({"status": "failure", "message": "An account with this username already exists."}))
        elif rows[0][3] == email:
            return make_response(
                jsonify({"status": "failure", "message": "An account with this email already exists."}))
        else:
            return make_response(jsonify({"status": "failure", "message": "Account already exists."}))

    now = datetime.datetime.now()
    date_joined = str(now.strftime('%d-%m-%Y %H:%M:%S'))

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)

    pfp_url = "https://google.com"

    c.execute(
        "INSERT INTO users(username, password_hash, email, pfp_url, date_joined, account_type) VALUES(?, ?, ?, ?, ?, ?)",
        (username, hashed, email, pfp_url, date_joined, "member"))  # TODO: add default pfp_url

    conn.commit()

    session["logged_in"] = True
    session["profile"] = {
        "name": username,
        "email": email,
        "pfp_url": pfp_url,
        "registration_date": date_joined,
    }

    return make_response(jsonify({"status": "success", "session": session["profile"]}))


@app.route("/v1/private/logout")
@cross_origin(supports_credentials=True)
def v1_private_logout():
    session["logged_in"] = False

    try:
        session.pop("profile")
    except KeyError:
        assert "No profile key... ignoring."

    return jsonify({"status": "success"})


@app.route("/v1/private/session/get")
@cross_origin(supports_credentials=True)
def v1_session_get():
    if not session.get("logged_in") or len(session.get("profile")) == 0:
        return make_response(jsonify({"status": "failure", "message": "Not logged in."}), 401)
    return jsonify({"status": "success", "session": session["profile"]})


@app.route("/v1/private/add_comment", methods=["POST"])
@cross_origin(supports_credentials=True)
@requires_auth
def add_comment():
    """
    Adds a comment to a video

    POST json:
    str video_id
    str comment_body
    """

    video_id = request.json["video_id"]
    comment = request.json["comment_body"]

    if video_id is None or comment is None:
        return make_response("Invalid GET Arguments", 400)

    if len(comment) == 0 or len(comment) > 2000:
        return make_response("Invalid Comment Length", 400)

    username = session.get("profile")["name"]

    now = datetime.datetime.now()
    date_submitted = str(now.strftime('%d-%m-%Y %H:%M:%S'))

    c = conn.cursor()
    c.execute("INSERT INTO comments(username, comment_body, video_id, date_posted) VALUES (?, ?, ?, ?)",
              (username, comment, video_id, date_submitted))
    conn.commit()

    return "success"


"""
Public API Routes
"""


@app.route("/v1/get_performances")
def get_performances():
    """
    Returns JSON object containing all performances, ordered newest first.

    GET args:
    bool ?reversed
    """
    is_reversed = str(request.args.get("reversed")).lower()

    c = conn.cursor()
    c.execute("SELECT * FROM performances")
    rows = c.fetchall()

    performances = []

    for i in rows:
        performances.append({
            "url_name": i[1],
            "name": i[2],
            "thumbnail_url": i[3],
            "date": i[4],
            "quality": i[5]
        })

    if is_reversed == "true":
        performances.reverse()

    return jsonify(performances)


@app.route("/v1/get_video")
def get_video():
    """
    Returns name, url_name, src, thumbnail_url, length

    GET args:
    str performance_id
    """
    performance_id = request.args.get("performance_id")

    if performance_id is None:
        return make_response("Invalid arg performance_id", 500)

    c = conn.cursor()
    c.execute("SELECT * FROM videos WHERE performance_name = %s", (performance_id,))
    rows = c.fetchall()

    videos = []

    for i in rows:
        videos.append({
            "name": i[2],
            "url_name": i[3],
            "src": i[4],
            "thumbnail_url": i[5],
            "length": i[6]
        })

    return jsonify(videos)


@app.route("/v1/get_comments")
def get_comments():
    """
    Returns comments of a given video_id

    GET args:
    str: video_id
    int: ?limit
    """
    video_id = request.args.get("video_id")
    limit = request.args.get("limit")

    if video_id is None or len(video_id) == 0:
        return make_response("Invalid video_id", 500)

    c = conn.cursor()

    if limit is None or int(limit) < 1:
        c.execute("SELECT * FROM comments WHERE video_id = %s ORDER BY id DESC", (video_id,))
    else:
        c.execute("SELECT * FROM comments WHERE video_id = %s ORDER BY id DESC LIMIT %s", (video_id, str(int(limit))))

    rows = c.fetchall()
    conn.commit()

    if len(rows) == 0:
        return {}

    final = []

    for i in rows:
        final.append({
            "username": i[1],
            "comment_body": i[2],
            "video_id": i[3],
            "date_posted": i[4]
        })

    return jsonify(final)


if __name__ == "__main__":
    atexit.register(close_connections)
    app.run(debug=True)

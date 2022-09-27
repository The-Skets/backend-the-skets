from flask import Flask, make_response, jsonify, request, session
from flask_cors import CORS, cross_origin
from functools import wraps
import datetime
import mariadb
import atexit
import bcrypt
import json
import os

from config import env

# env = os.environ  # For easier deployment

app = Flask(__name__)
app.secret_key = env["FLASK_SECRET_KEY"]
app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
privileged_account_types = ["Admin", "Band Member"]

cors = CORS(app, supports_credentials=True)  # TODO: Fix CORS for prod to prevent XSS

# TODO: Ensure all SQL operations obtain cursor from get_cursor()

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


def get_cursor():
    """
    This prevents the SQL connection from timing out. Re-connects on error.
    """
    global conn

    try:
        return conn.cursor()
    except mariadb.InterfaceError:
        print("refreshing connection")
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

        return conn.cursor()


def close_connections():
    """
    Called at shutdown of program.
    """
    conn.close()
    print("Closed Connection")


"""
Middleware
"""


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "logged_in" not in session or session["logged_in"] == False:
            return make_response(jsonify({"status": "failure", "message": "Unauthorized"}), 401)
        return f(*args, **kwargs)

    return decorated


def requires_band_member(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "account_type" not in session or session["account_type"] not in privileged_account_types:
            return make_response(jsonify({"status": "failure", "message": "Unauthorized"}), 401)
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

    c = get_cursor()

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
            "account_type": row[0][4],
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
        return make_response(jsonify({"status": "failure", "message": "Invalid Password"}), 400)

    if data["username"] is None or len(data["username"]) < 3:
        return make_response(jsonify({"status": "failure", "message": "Invalid Username"}), 400)

    if data["email"] is None or "@" not in data["email"]:
        return make_response(jsonify({"status": "failure", "message": "Invalid Email"}), 400)

    username = data["username"]
    password = data["password"]
    email = data["email"].lower().strip()

    c = get_cursor()

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
        "account_type": "member",
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
    str performance_id
    str comment_body
    """

    video_id = request.json["video_id"]
    performance_id = request.json["performance_id"]
    comment = request.json["comment_body"]

    if video_id is None or comment is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid request"}), 400)

    if len(comment) == 0 or len(comment) > 2000:
        return make_response(jsonify({"status": "failure", "message": "Invalid comment length"}), 400)

    if performance_id is None or len(performance_id) < 1:
        return make_response(jsonify({"status": "failure", "message": "Invalid performance_id"}), 400)

    username = session.get("profile")["name"]

    now = datetime.datetime.now()
    date_submitted = str(now.strftime('%d-%m-%Y %H:%M:%S'))

    c = get_cursor()
    c.execute(
        "INSERT INTO comments(username, comment_body, video_id, date_posted, performance_id) VALUES (?, ?, ?, ?, ?)",
        (username, comment, video_id, date_submitted, performance_id))
    conn.commit()

    return jsonify({"status": "success"})


"""
Admin routes
"""


@app.route("/v1/private/admin/get_performances")
# @requires_auth TODO: uncomment before deploying
# @requires_band_member
def v1_private_admin_get_performances():
    """
    Returns JSON object containing all performances, ordered newest first, with most associated data.
    Optional argument performance_id to just return the matching performance.
    Used in /admin/dashboard

    GET args:
    bool ?reversed
    string ?performance_id
    """

    is_reversed = str(request.args.get("reversed")).lower()

    performances = []
    comments = []
    videos = []

    c = get_cursor()

    if request.args.get("performance_id") is not None:
        performance_id = str(request.args.get("performance_id")).lower()

        c.execute("SELECT * FROM performances WHERE url_name = %s", (performance_id,))
        performance_row = c.fetchall()
        performance_row = performance_row[0]

        c.execute("SELECT * FROM comments WHERE performance_id = %s ORDER BY id DESC LIMIT 25", (performance_id,))
        comment_rows = c.fetchall()

        c.execute("SELECT * FROM videos WHERE performance_id = %s ORDER BY id DESC LIMIT 25", (performance_id,))
        video_rows = c.fetchall()

        for k in comment_rows:
            comments.append({
                "username": k[1],
                "comments_body": k[2],
                "video_id": k[3],
                "date_posted": k[4]
            })

        for j in video_rows:
            videos.append({
                "name": j[2],
                "url_name": j[3],
                "src": j[4],
                "thumbnail_url": j[5],
                "length": j[6]
            })

        performances.append({
            "url_name": performance_row[1],
            "name": performance_row[2],
            "thumbnail_url": performance_row[3],
            "date": performance_row[4],
            "quality": performance_row[5],
            "videos": videos,
            "comments": comments
        })

        if is_reversed == "true":
            performances.reverse()

        return jsonify(performances)

    c.execute("SELECT * FROM performances")
    rows = c.fetchall()

    for i in rows:
        c.execute("SELECT * FROM comments WHERE performance_id = %s ORDER BY id DESC LIMIT 25", (i[1],))
        comment_rows = c.fetchall()

        c.execute("SELECT * FROM videos WHERE performance_id = %s ORDER BY id DESC LIMIT 25", (i[1],))
        video_rows = c.fetchall()

        for k in comment_rows:
            comments.append({
                "username": k[1],
                "comments_body": k[2],
                "video_id": k[3],
                "date_posted": k[4]
            })

        for j in video_rows:
            videos.append({
                "name": j[2],
                "url_name": j[3],
                "src": j[4],
                "thumbnail_url": j[5],
                "length": j[6]
            })

        performances.append({
            "url_name": i[1],
            "name": i[2],
            "thumbnail_url": i[3],
            "date": i[4],
            "quality": i[5],
            "videos": videos,
            "comments": comments
        })

    if is_reversed == "true":
        performances.reverse()

    return jsonify(performances)


@app.route("/v1/private/admin/delete_performance/<id>", methods=["DELETE"])
@requires_auth
@requires_band_member
def v1_private_admin_delete_performance(id):
    """
    Deletes performance matching the performance_id of <id>.
    Must use DELETE method.
    """
    # TODO: Add actual delete logic.
    print("deleting " + id)
    return make_response('', 204)


@app.route("/v1/private/admin/patch_performance/<id>", methods=["PATCH"])  # yes, this is the wrong way to use PATCH
# @requires_auth
# @requires_band_member TODO: Uncomment this
def v1_private_admin_patch_performance(id):
    """
    Modifies performance matching the performance_id of <id>.
    Must use PATCH method.
    """
    # TODO: Add actual delete logic.
    valid_patches = {
        "name": "friendly_name",
        "thumbnail url": "image_src",
        "date": "date_of_event",
        "quality": "quality"
    }

    data = json.loads(request.data)
    print(data)

    if id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid performance_id"}), 400)

    if data.get("patching") is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid patching (Not provided)"}), 400)

    if data.get("new_value") is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid new_value"}), 400)

    performance_id = str(id).strip()
    patching = str(data.get("patching")).strip()
    new_value = str(data.get("new_value")).strip()

    if valid_patches.get(patching) is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid patching (Not valid)"}), 400)

    safe_patching = valid_patches[patching]

    c = get_cursor()
    # This string manipulation is (hopefully) safe as it's validated against the dictionary
    c.execute(f"UPDATE performances SET {safe_patching} = %s WHERE url_name = %s", (new_value, performance_id))
    conn.commit()

    return jsonify({"status": "success"})


@app.route("/v1/private/admin/get_videos")
# @requires_auth
# @requires_band_member TODO: Uncomment this
def v1_private_admin_get_videos():
    """
    Returns all videos

    GET args:
    string ?reversed
    """
    videos = []

    reversed = request.args.get("reversed")
    if reversed == "true":
        c = get_cursor()
        c.execute("SELECT * FROM videos ORDER BY id DESC")
    else:
        c = get_cursor()
        c.execute("SELECT * FROM videos")

    rows = c.fetchall()
    for i in rows:
        videos.append({
            "performance_id": i[1],
            "name": i[2],
            "url_name": i[3],
            "src": i[4],
            "thumbnail_url": i[5],
            "length": i[6]
        })

    return jsonify(videos)


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

    c = get_cursor()
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
        return make_response(jsonify({"status": "failure", "message": "Invalid performance_id"}), 400)

    c = get_cursor()
    c.execute("SELECT * FROM videos WHERE performance_name = %s", (performance_id,))
    rows = c.fetchall()

    videos = []
    x = 0

    for i in rows:
        videos.append({
            "id": str(x),
            "name": i[2],
            "url_name": i[3],
            "src": i[4],
            "thumbnail_url": i[5],
            "length": i[6]
        })
        x += 1

    return jsonify(videos)


@app.route("/v1/get_comments")
@cross_origin(supports_credentials=True)
def get_comments():
    """
    Returns comments of a given video_id

    GET args:
    str: video_id
    str: performance_id
    int: ?limit
    """
    video_id = request.args.get("video_id")
    performance_id = request.args.get("performance_id")
    limit = request.args.get("limit")

    if video_id is None or len(video_id) == 0 or performance_id is None or len(performance_id) == 0:
        return make_response(jsonify({"status": "failure", "message": "Invalid video_id or performance_id"}), 400)

    c = get_cursor()

    if limit is None or int(limit) < 1:
        c.execute("SELECT * FROM comments WHERE video_id = %s AND performance_id = %s ORDER BY id DESC",
                  (video_id, performance_id))
    else:
        c.execute("SELECT * FROM comments WHERE video_id = %s AND performance_id = %s ORDER BY id DESC LIMIT %s",
                  (video_id, performance_id, str(int(limit))))

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


"""
Debug Routes
"""


@app.route("/debug")
@cross_origin(supports_credentials=True)
def debug():
    print(session.get("logged_in"))
    print(session.get("profile"))
    return f"""
    session['logged_in']: <code>{session.get('logged_in')}</code>
    session['profile']: <code>{session.get("profile")}</code>
    """


if __name__ == "__main__":
    atexit.register(close_connections)
    app.run(debug=True, host="0.0.0.0")

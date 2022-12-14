from flask import Flask, make_response, jsonify, request, session, send_from_directory
from urllib.parse import urlparse, parse_qs
from werkzeug.utils import secure_filename
from flask_cors import CORS, cross_origin
from functools import wraps
import requests
import datetime
import mariadb
import atexit
import bcrypt
import math
import json
import re
import os

from config import env

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
FORBIDDEN_NAMES = ["default"]  # Ensure all these are lower-case.
DOMAIN = 'http://192.168.1.209:5000'

app = Flask(__name__)

app.secret_key = env["FLASK_SECRET_KEY"]
app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=False)  # TODO: set SESSION_COOKIE_SECURE=True
app.config[
    'UPLOAD_FOLDER'] = 'C:\\Users\\annan\\Documents\projects\\the-skets-rewrite\\backend-the-skets\\profile_pictures'  # TODO: Change this before deployment
app.config[
    'PERFORMANCE_UPLOAD_FOLDER'] = "C:\\Users\\annan\\Documents\projects\\the-skets-rewrite\\backend-the-skets\\performance_images"  # TODO: Change this before deployment

privileged_account_types = ["Admin", "Band Member"]

cors = CORS(app, supports_credentials=True)  # TODO: Fix CORS for prod to prevent XSS


# TODO: Ensure all SQL operations obtain cursor from get_cursor()
# TODO: Ensure all strip()'s are called after variable is validated to exist.


def create_connection_pool():
    """Creates and returns a Connection Pool"""

    pool = mariadb.ConnectionPool(
        host=env["SQL_HOST"],
        port=3306,
        user=env["SQL_USERNAME"],
        password=env["SQL_PASSWORD"],
        pool_name="TheSkets",
        database="TheSkets",
        pool_size=5
    )

    return pool


pool = create_connection_pool()

"""
Serverside Functions
"""


def get_connection():
    """
    This prevents the SQL connection from timing out. Re-connects on error.
    """
    global conn

    try:
        return pool.get_connection()
    except mariadb.PoolError as e:
        print(e)
        print("Creating fallback connection")
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

        return conn


def close_connections():
    """
    Called at shutdown of program.
    """
    try:
        conn.close()
    except:
        print("no conn variable, ignoring")
    pool.close()
    print("Closed Connection(s)")


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def convert_youtube_duration_to_seconds(duration):
    """
    Taken from "https://stackoverflow.com/a/58004773/10981578".
    Takes ISO 8601 string and converts it into seconds of duration.
    """
    day_time = duration.split('T')
    day_duration = day_time[0].replace('P', '')
    day_list = day_duration.split('D')

    if len(day_list) == 2:
        day = int(day_list[0]) * 60 * 60 * 24
    else:
        day = 0

    hour_list = day_time[1].split('H')
    if len(hour_list) == 2:
        hour = int(hour_list[0]) * 60 * 60
        hour_list = hour_list[1]
    else:
        hour = 0
        hour_list = hour_list[0]

    minute_list = hour_list.split('M')

    if len(minute_list) == 2:
        minute = int(minute_list[0]) * 60
        minute_list = minute_list[1]
    else:
        minute = 0
        minute_list = minute_list[0]

    second_list = minute_list.split('S')

    if len(second_list) == 2:
        second = int(second_list[0])
    else:
        second = 0

    return day + hour + minute + second


def convert_youtube_playlist_to_temp_performance(playlist_id, url_name, friendly_name, image_src, date_of_event,
                                                 quality, unix_timestamp):
    """
    Converts YouTube playlist to a temporary performance
    that can be edited by the user before deployment.
    Ran as a new process.
    """
    r = requests.get(
        f"https://youtube.googleapis.com/youtube/v3/playlistItems?part=snippet&playlistId={playlist_id}&key={env['GOOGLE_API_KEY']}&maxResults=50")

    if r.status_code != 200 and r.status_code != 204:
        return False

    conn = get_connection()
    c = conn.cursor()

    c.execute("DELETE FROM temp_videos")
    c.execute("DELETE FROM temp_performances")
    c.execute(
        "INSERT INTO temp_performances(url_name, friendly_name, image_src, date_of_event, quality, unix_timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (url_name, friendly_name, image_src, date_of_event, quality, unix_timestamp))

    resp = r.json()
    for i in resp["items"]:
        title = i["snippet"]["title"]
        vid_url_name = secure_filename(title.strip().replace(" ", "_"))
        thumbnail = i["snippet"]["thumbnails"]["default"]["url"]
        video_id = i["snippet"]["resourceId"]["videoId"]

        vid_r = requests.get(
            f"https://www.googleapis.com/youtube/v3/videos?part=contentDetails&id={video_id}&key={env['GOOGLE_API_KEY']}")

        r_resp = vid_r.json()

        video_duration = convert_youtube_duration_to_seconds(r_resp['items'][0]['contentDetails']['duration'])

        minutes = str(math.floor(video_duration / 60))
        seconds = str(math.floor(video_duration % 60))

        if len(seconds) == 1:
            seconds = "0" + seconds

        converted_duration = f"{minutes}:{seconds}"

        c.execute(
            "INSERT INTO temp_videos(performance_id, friendly_name, url_name, src, thumbnail_url, length) VALUES (?, ?, ?, ?, ?, ?)",
            (url_name, title, vid_url_name, video_id, thumbnail, converted_duration))

    conn.commit()
    conn.close()

    return True


"""
Middleware
"""


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "logged_in" not in session or session["logged_in"] is False:
            print("Not Logged In", session)  # TODO: Remove debug prints
            return make_response(jsonify({"status": "failure", "message": "Unauthorized"}), 401)
        return f(*args, **kwargs)

    return decorated


def requires_band_member(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "profile" not in session or "account_type" not in session["profile"] or session["profile"][
                "account_type"] not in privileged_account_types:
            print("Not Band Member", session)  # TODO: Remove debug prints
            return make_response(jsonify({"status": "failure", "message": "Unauthorized"}), 401)
        return f(*args, **kwargs)

    return decorated


"""
Private API Routes
"""


@app.route("/v1/private/sign_in", methods=["POST"])
@cross_origin(supports_credentials=True)
def v1_private_sign_in():
    data = request.get_json()

    if data["password"] is None or data["username"] is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid Password or Username"}), 400)

    username = data["username"]
    password = data["password"]

    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE username = %s", (username,))
    row = c.fetchall()
    conn.close()

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

    if data["password"] is None or len(data["password"]) < 6:
        return make_response(jsonify({"status": "failure", "message": "Password too short"}), 400)

    if data["username"] is None or len(data["username"]) < 3:
        return make_response(jsonify({"status": "failure", "message": "Username too short"}), 400)

    if data["email"] is None or "@" not in data["email"]:
        return make_response(jsonify({"status": "failure", "message": "Invalid Email"}), 400)

    username = data["username"].strip()
    password = data["password"]
    email = data["email"].lower().strip()  # DO NOT REMOVE

    if username.lower() in FORBIDDEN_NAMES:
        return make_response(jsonify({"status": "failure", "message": "Invalid username."}), 400)

    if secure_filename(username) != username:
        return make_response(jsonify({"status": "failure", "message": "Invalid characters in username."}), 400)

    if not re.match("^[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)?$", username):
        return make_response(jsonify({"status": "failure", "message": "Invalid characters in username."}), 400)

    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
    rows = c.fetchall()

    if len(rows) > 0:
        if rows[0][1].lower() == username.lower():
            conn.close()
            return make_response(
                jsonify({"status": "failure", "message": "An account with this username already exists."}))
        elif rows[0][3].lower() == email:
            conn.close()
            return make_response(
                jsonify({"status": "failure", "message": "An account with this email already exists."}))
        else:
            conn.close()
            return make_response(jsonify({"status": "failure", "message": "Account already exists."}))

    now = datetime.datetime.now()
    date_joined = str(now.strftime('%d-%m-%Y %H:%M:%S'))

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)

    pfp_url = DOMAIN + "/v1/pfp/default.jpg"

    c.execute(
        "INSERT INTO users(username, password_hash, email, pfp_url, date_joined, account_type) VALUES(?, ?, ?, ?, ?, ?)",
        (username, hashed, email, pfp_url, date_joined, "member"))

    conn.commit()
    conn.close()

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

    conn = get_connection()
    c = conn.cursor()

    c.execute(
        "INSERT INTO comments(username, comment_body, video_id, date_posted, performance_id) VALUES (?, ?, ?, ?, ?)",
        (username, comment, video_id, date_submitted, performance_id))
    conn.commit()
    conn.close()

    return jsonify({"status": "success"})


@app.route("/v1/private/new_profile_image", methods=["POST"])
@requires_auth
def v1_private_new_profile_image():
    print(request)
    if "file" not in request.files:
        print("file not in request.files")
        return make_response(jsonify({"status": "failure", "message": "No image provided."}), 400)

    file = request.files['file']

    if file.filename == '':
        print("filename empty")
        return make_response(jsonify({"status": "failure", "message": "No image provided."}), 400)

    if not session.get("profile") or not session.get("profile")["name"]:
        return make_response(jsonify({"status": "failure", "message": "Error with session, please login again."}), 400)

    if file and allowed_file(file.filename):
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(session.get("profile")["name"] + ".jpg")))

        conn = get_connection()
        c = conn.cursor()

        c.execute("UPDATE users SET pfp_url = %s WHERE email = %s", (
            DOMAIN + "/v1/pfp/" + secure_filename(session.get("profile")["name"] + ".jpg"),
            session.get("profile")["email"]))

        # I'm not sure why this doesn't work in-place. probably something to do with the list depth.
        profile = session["profile"]
        profile["pfp_url"] = (DOMAIN + "/v1/pfp/" + secure_filename(session.get("profile")["name"] + ".jpg"))
        session["profile"] = profile

        conn.commit()
        conn.close()

        return jsonify({"status": "success"})

    return make_response(jsonify({"status": "failure", "message": "Error with image."}), 400)


"""
Admin routes
"""


@app.route("/v1/private/admin/get_performances")
@requires_auth
@requires_band_member
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

    conn = get_connection()
    c = conn.cursor()

    if request.args.get("performance_id") is not None:
        performance_id = str(request.args.get("performance_id")).lower()

        c.execute("SELECT * FROM performances WHERE url_name = %s ORDER BY unix_timestamp", (performance_id,))
        performance_row = c.fetchall()
        performance_row = performance_row[0]

        c.execute("SELECT * FROM comments WHERE performance_id = %s ORDER BY id DESC LIMIT 25", (performance_id,))
        comment_rows = c.fetchall()

        c.execute("SELECT * FROM videos WHERE performance_id = %s ORDER BY id DESC LIMIT 25", (performance_id,))
        video_rows = c.fetchall()

        conn.close()

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

    c.execute("SELECT * FROM performances ORDER BY unix_timestamp")
    rows = c.fetchall()

    for i in rows:
        c.execute("SELECT * FROM comments WHERE performance_id = %s ORDER BY id DESC LIMIT 25", (i[1],))
        comment_rows = c.fetchall()

        c.execute("SELECT * FROM videos WHERE performance_id = %s ORDER BY id DESC LIMIT 25", (i[1],))
        video_rows = c.fetchall()

        conn.close()

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
    if id == None:
        return make_response(jsonify({"status": "failure", "message": "Invalid performance id"}))

    id = str(id).strip()

    conn = get_connection()
    c = conn.cursor()

    c.execute("DELETE FROM performances WHERE url_name = %s", (id,))
    c.execute("DELETE FROM videos WHERE performance_id = %s", (id,))
    c.execute("DELETE FROM comments WHERE performance_id = %s", (id,))

    conn.commit()
    conn.close()

    return make_response('', 204)


@app.route("/v1/private/admin/patch_performance/<id>", methods=["PATCH"])  # yes, this is the wrong way to use PATCH
@requires_auth
@requires_band_member
def v1_private_admin_patch_performance(id):
    """
    Modifies performance matching the performance_id of <id>.
    Must use PATCH method.
    """

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
    patching = str(data.get("patching")).strip().lower()
    new_value = str(data.get("new_value")).strip()

    if valid_patches.get(patching) is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid patching (Not valid)"}), 400)

    safe_patching = valid_patches[patching]

    conn = get_connection()
    c = conn.cursor()

    # This string manipulation is (hopefully) safe as it's validated against the dictionary
    c.execute(f"UPDATE performances SET {safe_patching} = %s WHERE url_name = %s", (new_value, performance_id))
    conn.commit()
    conn.close()

    return jsonify({"status": "success"})


@app.route("/v1/private/new_performance_image", methods=["POST"])
@requires_auth
@requires_band_member
def v1_private_new_performance_image():
    performance_id = request.args.get("performance_id")

    if performance_id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid performance_id"}))

    print(request)

    if "file" not in request.files:
        print("file not in request.files")
        return make_response(jsonify({"status": "failure", "message": "No image provided."}), 400)

    file = request.files['file']
    if file.filename == '':
        print("filename empty")
        return make_response(jsonify({"status": "failure", "message": "No image provided."}), 400)

    if file and allowed_file(file.filename):
        file.save(os.path.join(app.config['PERFORMANCE_UPLOAD_FOLDER'], secure_filename(performance_id + ".webp")))

        conn = get_connection()
        c = conn.cursor()

        c.execute("UPDATE performances SET image_src = %s WHERE performance_id = %s", (
                DOMAIN + "/v1/performance_images/" + secure_filename(performance_id + ".webp")), performance_id)

        conn.commit()
        conn.close()

        return jsonify({"status": "success"})

    return make_response(jsonify({"status": "failure", "message": "Error with image."}), 400)


@app.route("/v1/private/admin/new_performance", methods=["POST"])
@requires_auth
@requires_band_member
def v1_private_admin_new_performance():
    print(request.form)

    playlist = request.form.get("playlist")
    friendly_name = request.form.get("friendly-name")
    url_name = request.form.get("url-name")
    date = request.form.get("date-of-performance")
    quality = request.form.get("quality")
    unix_timestamp = 0

    if None in [playlist, friendly_name, url_name, date, quality]:
        return make_response(jsonify({"status": "failure", "message": "Invalid form inputs"}), 400)

    if "http" not in playlist:
        return make_response(jsonify({"status": "failure", "message": "Invalid playlist"}), 400)

    if "/" not in date:
        return make_response(
            jsonify({"status": "failure", "message": "Invalid date. Ensure date is in format DD/MM/YYYY"}), 400)

    try:
        unix_timestamp = datetime.datetime.timestamp(
            datetime.datetime(int(date.split("/")[2]), int(date.split("/")[1]), int(date.split("/")[0]))) * 1000
    except (ValueError, IndexError):
        return make_response(
            jsonify({"status": "failure", "message": "Invalid date. Ensure date is in format DD/MM/YYYY"}), 400)

    if secure_filename(url_name) != url_name:
        return make_response(jsonify({"status": "failure", "message": "Invalid url_name"}), 400)

    playlist = urlparse(playlist)
    playlist = parse_qs(playlist.query)["list"][0]

    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM performances WHERE url_name = %s ORDER BY unix_timestamp", (url_name,))
    rows = c.fetchall()
    conn.close()

    if len(rows) > 0:
        return make_response(jsonify({"status": "failure", "message": "Duplicate url_name."}), 400)

    if "file" not in request.files:
        print("file not in request.files")
        return make_response(jsonify({"status": "failure", "message": "No image provided."}), 400)

    file = request.files['file']
    if file.filename == '':
        print("filename empty")
        return make_response(jsonify({"status": "failure", "message": "No image provided."}), 400)

    if file and allowed_file(file.filename):
        file.save(os.path.join(app.config['PERFORMANCE_UPLOAD_FOLDER'], secure_filename(url_name + ".webp")))

        image_src = DOMAIN + "/v1/performance_images/" + secure_filename(url_name + ".webp")

        # proc = Process(target=convert_youtube_playlist_to_temp_performance, args=(playlist, url_name, friendly_name, image_src, date, quality))
        # proc.start()
        # proc.join()

        convert_youtube_playlist_to_temp_performance(playlist, url_name, friendly_name, image_src, date, quality,
                                                     unix_timestamp)

        return jsonify({"status": "success"})

    return make_response(jsonify({"status": "failure", "message": "Error with image."}), 400)


@app.route("/v1/private/admin/get_temporary_performance")
@requires_auth
@requires_band_member
def v1_private_admin_get_temporary_performance():
    conn = get_connection()
    c = conn.cursor()

    performance_id = str(request.args.get("performance_id")).lower()
    is_reversed = str(request.args.get("is_reversed")).lower()

    c.execute("SELECT * FROM temp_performances WHERE url_name = %s", (performance_id,))
    performance_row = c.fetchall()

    try:
        performance_row = performance_row[0]
    except IndexError:
        conn.close()
        return make_response(jsonify({"status": "failure", "message": "Performance does not exist."}), 400)

    c.execute("SELECT * FROM temp_videos WHERE performance_id = %s ORDER BY id DESC LIMIT 25", (performance_id,))
    video_rows = c.fetchall()

    conn.close()

    performances = []
    videos = []

    for j in video_rows:
        videos.append({
            "id": j[0],
            "performance_id": j[1],
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
    })

    if is_reversed == "true":
        performances.reverse()

    return jsonify(performances)


@app.route("/v1/private/admin/publish_temporary_performance")
@requires_auth
@requires_band_member
def v1_private_admin_publish_temporary_performance():
    """
    TODO: document.
    """
    performance_id = request.args.get("performance_id")
    performance_id = performance_id.strip()

    if performance_id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid performance_id"}), 400)

    conn = get_connection()
    c = conn.cursor()

    c.execute(
        "INSERT INTO performances(url_name, friendly_name, image_src, date_of_event, quality, unix_timestamp) SELECT url_name, friendly_name, image_src, date_of_event, quality, unix_timestamp FROM temp_performances WHERE url_name = %s",
        (performance_id,))
    c.execute(
        "INSERT INTO videos(performance_id, friendly_name, url_name, src, thumbnail_url, length) SELECT performance_id, friendly_name, url_name, src, thumbnail_url, length FROM temp_videos WHERE performance_id = %s",
        (performance_id,))

    conn.commit()
    conn.close()

    return jsonify({"status": "success"})


@app.route("/v1/private/admin/delete_video/<performance_id>/<video_id>", methods=["DELETE"])
@requires_auth
@requires_band_member
def v1_private_admin_delete_video(performance_id, video_id):
    """
    Deletes video matching the supplied ids.
    Must use DELETE method.
    """

    if performance_id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid performance_id"}), 400)
    if video_id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid video_id"}), 400)

    video_id = str(video_id).strip()
    performance_id = str(performance_id).strip()

    conn = get_connection()
    c = conn.cursor()

    c.execute("DELETE FROM videos WHERE url_name = %s AND performance_id = %s", (video_id, performance_id,))

    conn.commit()
    conn.close()

    return make_response("", 204)


@app.route("/v1/private/admin/patch_video/<performance_id>/<video_id>",
           methods=["PATCH"])  # yes, this is the wrong way to use PATCH
@requires_auth
@requires_band_member
def v1_private_admin_patch_video(performance_id, video_id):
    """
    Modifies video matching the supplied ids.
    Must use PATCH method.
    """

    valid_patches = {
        "name": "friendly_name",
        "url_name": "url_name",
        "thumbnail url": "thumbnail_url",
        "length": "length",
        "youtube video": "src",
        "performance": "performance_id"
    }

    data = json.loads(request.data)
    print(data)

    if video_id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid id"}), 400)

    if performance_id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid performance_id"}), 400)

    if data.get("patching") is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid patching (Not provided)"}), 400)

    if data.get("new_value") is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid new_value"}), 400)

    video_id = str(video_id).strip()
    performance_id = str(performance_id).strip()

    patching = str(data.get("patching")).strip().lower()
    new_value = str(data.get("new_value")).strip()

    if valid_patches.get(patching) is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid patching (Not valid)"}), 400)

    safe_patching = valid_patches[patching]

    conn = get_connection()
    c = conn.cursor()

    # This string manipulation is (hopefully) safe as it's validated against the dictionary
    c.execute(f"UPDATE videos SET {safe_patching} = %s WHERE performance_id = %s AND url_name = %s",
              (new_value, performance_id, video_id))
    conn.commit()
    conn.close()

    return jsonify({"status": "success"})


@app.route("/v1/private/admin/patch_temporary_video/<youtube_video_id>", methods=["PATCH"])
@requires_auth
@requires_band_member
def v1_private_admin_patch_temporary_video(youtube_video_id):
    """
    Modifies temporary video matching the supplied ids.
    Must use PATCH method.
    """

    valid_patches = {
        "name": "friendly_name",
        "url_name": "url_name",
        "thumbnail url": "thumbnail_url",
        "length": "length",
        "youtube video": "src",
    }

    data = json.loads(request.data)
    print(data)

    if youtube_video_id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid youtube_video_id"}), 400)

    if data.get("patching") is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid patching (Not provided)"}), 400)

    if data.get("new_value") is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid new_value"}), 400)

    youtube_video_id = str(youtube_video_id).strip()

    patching = str(data.get("patching")).strip().lower()
    new_value = str(data.get("new_value")).strip()

    if valid_patches.get(patching) is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid patching (Not valid)"}), 400)

    safe_patching = valid_patches[patching]

    conn = get_connection()
    c = conn.cursor()

    # This string manipulation is (hopefully) safe as it's validated against the dictionary
    c.execute(f"UPDATE temp_videos SET {safe_patching} = %s WHERE src = %s",
              (new_value, youtube_video_id))
    conn.commit()
    conn.close()

    return jsonify({"status": "success"})


@app.route("/v1/private/admin/delete_temporary_video/<youtube_video_id>", methods=["DELETE"])
@requires_auth
@requires_band_member
def v1_private_admin_delete_temporary_video(youtube_video_id):
    """
    Deletes temporary video matching the supplied ids.
    Must use DELETE method.
    """

    if youtube_video_id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid youtube_video_id"}), 400)

    youtube_video_id = str(youtube_video_id).strip()

    conn = get_connection()
    c = conn.cursor()

    c.execute("DELETE FROM temp_videos WHERE src = %s", (youtube_video_id,))

    conn.commit()
    conn.close()

    return make_response("", 204)


@app.route("/v1/private/admin/get_videos")
@requires_auth
@requires_band_member
def v1_private_admin_get_videos():
    """
    Returns all videos, can be filtered by performance_id and url_name.
    Filtering requires BOTH performance_id and url_name, but is optional.

    GET args:
    string ?reversed
    string ?performance_id
    string ?url_name
    """
    videos = []

    reversed = request.args.get("reversed")
    performance_id = request.args.get("performance_id")
    video_id = request.args.get("video_id")

    conn = get_connection()
    c = conn.cursor()

    if not (performance_id is None or video_id is None):
        performance_id = performance_id.strip()
        video_id = video_id.strip()

        if reversed == "true":
            c.execute("SELECT * FROM videos WHERE performance_id = %s AND url_name = %s ORDER BY id DESC",
                      (performance_id, video_id))
        else:
            c.execute("SELECT * FROM videos WHERE performance_id = %s AND url_name = %s", (performance_id, video_id))
    else:
        if reversed == "true":
            c.execute("SELECT * FROM videos ORDER BY id DESC")
        else:
            c.execute("SELECT * FROM videos")

    rows = c.fetchall()
    conn.close()

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


@app.route("/v1/private/admin/get_comments")
@requires_auth
@requires_band_member
def v1_private_admin_get_comments():
    """
    Returns all comments

    GET Args:
    int ?limit
    str ?comment_id
    """
    limit = request.args.get("limit")
    comment_id = request.args.get("comment_id")

    conn = get_connection()
    c = conn.cursor()

    if comment_id is not None:
        c.execute("SELECT * FROM comments WHERE id = %s", (str(int(comment_id)),))
    elif limit is None or int(limit) < 1:
        c.execute("SELECT * FROM comments ORDER BY id DESC")
    else:
        c.execute("SELECT * FROM comments ORDER BY id DESC LIMIT %s", (str(int(limit)),))

    rows = c.fetchall()
    conn.close()

    if len(rows) == 0:
        return jsonify({})

    final = []

    for i in rows:
        final.append({
            "id": i[0],
            "username": i[1],
            "comment_body": i[2],
            "video_id": i[3],
            "performance_id": i[5],
            "date_posted": i[4]
        })

    return jsonify(final)


@app.route("/v1/private/admin/delete_comment/<id>", methods=["DELETE"])
@requires_auth
@requires_band_member
def v1_private_admin_delete_comment(id):
    """
    Deletes comment matching id. Must use DELETE method.
    """
    if id is None or int(id) < 0:
        return make_response(jsonify({"status": "failure", "message": "Invalid id"}), 400)

    conn = get_connection()
    c = conn.cursor()

    c.execute("DELETE FROM comments WHERE id = %s", (id,))
    conn.commit()
    conn.close()

    return make_response("", 204)


@app.route("/v1/private/admin/get_users")
@requires_auth
@requires_band_member
def v1_private_admin_get_users():
    """
    Returns all users. Optional argument id returns only one user matching the id.

    GET Args:
    str ?reversed
    int ?limit
    str ?id
    """
    reversed = request.args.get("reversed")
    limit = request.args.get("limit")
    id = request.args.get("id")

    conn = get_connection()
    c = conn.cursor()

    if id is not None:
        users = []
        c.execute("SELECT * FROM users WHERE id = %s", (int(id),))
        rows = c.fetchall()

        conn.close()

        for i in rows:
            users.append({
                "id": i[0],
                "username": i[1],
                "email": i[3],
                "account_type": i[4],
                "date_joined": i[5]
            })

        return jsonify(users)

    if str(limit) == 0:
        limit = "0"

    if reversed and limit:
        c.execute("SELECT * FROM users ORDER BY id DESC LIMIT %s", (str(int(limit)),))
    elif reversed:
        c.execute("SELECT * FROM users ORDER BY id DESC")
    elif limit:
        c.execute("SELECT * FROM users LIMIT %s", (str(int(limit)),))
    else:
        c.execute("SELECT * FROM users")

    rows = c.fetchall()
    conn.close()

    users = []

    for i in rows:
        users.append({
            "id": i[0],
            "username": i[1],
            "email": i[3],
            "account_type": i[4],
            "date_joined": i[5]
        })

    return jsonify(users)


@app.route("/v1/private/admin/patch_user/<id>", methods=["PATCH"])
@requires_auth
@requires_band_member
def v1_private_admin_patch_user(id):
    """
    Modifies user matching the <id>.
    Must use PATCH method.
    """

    valid_patches = {
        "account type": "account_type",
    }

    data = json.loads(request.data)
    print(data)

    if id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid id"}), 400)

    if data.get("patching") is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid patching (Not provided)"}), 400)

    if data.get("new_value") is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid new_value"}), 400)

    id = int(str(id).strip())
    patching = str(data.get("patching")).strip().lower()
    new_value = str(data.get("new_value")).strip()

    if valid_patches.get(patching) is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid patching (Not valid)"}), 400)

    safe_patching = valid_patches[patching]

    conn = get_connection()
    c = conn.cursor()

    # This string manipulation is (hopefully) safe as it's validated against the dictionary
    c.execute(f"UPDATE users SET {safe_patching} = %s WHERE id = %s", (new_value, id))

    conn.commit()
    conn.close()

    return jsonify({"status": "success"})


@app.route("/v1/private/admin/delete_user/<id>", methods=["PATCH"])
@requires_auth
@requires_band_member
def v1_private_admin_delete_user(id):
    if id is None:
        return make_response(jsonify({"status": "failure", "message": "Invalid id"}))

    conn = get_connection()
    c = conn.cursor()

    c.execute("DELETE FROM users WHERE id = %s", (int(id),))

    conn.commit()
    conn.close()

    return make_response("", 204)


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

    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM performances ORDER BY unix_timestamp")
    rows = c.fetchall()
    conn.close()

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

    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM videos WHERE performance_id = %s", (performance_id,))
    rows = c.fetchall()

    conn.close()

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

    conn = get_connection()
    c = conn.cursor()

    if limit is None or int(limit) < 1:
        c.execute("SELECT * FROM comments WHERE video_id = %s AND performance_id = %s ORDER BY id DESC",
                  (video_id, performance_id))
    else:
        c.execute("SELECT * FROM comments WHERE video_id = %s AND performance_id = %s ORDER BY id DESC LIMIT %s",
                  (video_id, performance_id, str(int(limit))))

    rows = c.fetchall()
    conn.close()

    if len(rows) == 0:
        return {}

    final = []

    for i in rows:
        final.append({
            "id": i[0],
            "username": i[1],
            "comment_body": i[2],
            "video_id": i[3],
            "date_posted": i[4]
        })

    return jsonify(final)


@app.route("/v1/pfp/<path:path>")
def v1_pfp(path):
    return send_from_directory('profile_pictures', path)


@app.route("/v1/performance_images/<path:path>")
def v1_performance_images(path):
    return send_from_directory('performance_images', path)


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

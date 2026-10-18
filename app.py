import json
import os
import re
import secrets
import threading
from datetime import datetime
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

SITE_NAME = os.environ.get('SITE_NAME', 'Video Player')
OWNER_ID = os.environ.get('OWNER_ID', '541379256878366746')

CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID')
CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI', 'http://localhost:5000/callback')
DISCORD_AUTHORIZE_URL = 'https://discord.com/oauth2/authorize'
DISCORD_TOKEN_URL = 'https://discord.com/api/oauth2/token'
DISCORD_USER_URL = 'https://discord.com/api/users/@me'

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'videos')
ALLOWED_EXTENSIONS = {'mp4', 'webm', 'ogg'}
VIDEO_MIME_TYPES = {'mp4': 'video/mp4', 'webm': 'video/webm', 'ogg': 'video/ogg'}
MAX_UPLOAD_MB = 500
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_MB * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------------------------------------------------------- data store
DATA_FILE = os.path.join(app.root_path, 'data.json')
_data_lock = threading.Lock()


def load_data():
    try:
        with open(DATA_FILE, encoding='utf-8') as f:
            raw = json.load(f)
    except (OSError, ValueError):
        raw = {}
    users = raw.get('users')
    videos = raw.get('videos')
    banned = raw.get('banned')
    data = {
        'maintenance': bool(raw.get('maintenance', False)),
        'open_uploads': bool(raw.get('open_uploads', False)),
        'users': users if isinstance(users, dict) else {},
        'videos': videos if isinstance(videos, dict) else {},
        'banned': banned if isinstance(banned, dict) else {},
        'next_video_id': raw.get('next_video_id') if isinstance(raw.get('next_video_id'), int) else 1,
    }
    try:
        if data['videos']:
            data['next_video_id'] = max(data['next_video_id'],
                                        max(int(k) for k in data['videos']) + 1)
    except ValueError:
        pass
    return data


def save_data(data):
    tmp = DATA_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, DATA_FILE)


def modify_data(change):
    with _data_lock:
        data = load_data()
        change(data)
        save_data(data)


# ------------------------------------------------------------------- helpers
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def wants_json():
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'


def sync_videos():
    """Match data.json to the files on disk. Existing files get an ID and an
    'Unknown' uploader; entries whose file is gone are dropped."""
    def change(data):
        videos = data['videos']
        on_disk = {n for n in os.listdir(UPLOAD_FOLDER) if allowed_file(n)}

        for key in [k for k, v in videos.items() if v.get('filename') not in on_disk]:
            del videos[key]

        known = {v['filename'] for v in videos.values()}
        new_files = sorted(on_disk - known,
                           key=lambda n: os.path.getmtime(os.path.join(UPLOAD_FOLDER, n)))
        for name in new_files:
            path = os.path.join(UPLOAD_FOLDER, name)
            vid = data['next_video_id']
            data['next_video_id'] = vid + 1
            base = name.split('_', 1)[1] if '_' in name else name
            videos[str(vid)] = {
                'id': vid,
                'filename': name,
                'title': os.path.splitext(base)[0].replace('_', ' ')[:80] or 'Untitled',
                'uploader_id': None,
                'uploader_name': 'Unknown',
                'uploaded_at': datetime.fromtimestamp(os.path.getmtime(path)).isoformat(),
                'size': os.path.getsize(path),
            }
    modify_data(change)


def decorate(video):
    ext = video['filename'].rsplit('.', 1)[1].lower()
    try:
        when = datetime.fromisoformat(video['uploaded_at'])
    except (KeyError, ValueError):
        when = datetime.now()
    return {
        **video,
        'mime': VIDEO_MIME_TYPES.get(ext, 'video/mp4'),
        'size_mb': round(video.get('size', 0) / (1024 * 1024), 1),
        'uploaded': when.strftime('%b %d, %Y %H:%M'),
    }


def all_videos():
    vids = sorted(g.data['videos'].values(), key=lambda v: v['id'], reverse=True)
    return [decorate(v) for v in vids]


def can_delete(video):
    if g.is_staff:
        return True
    return bool(g.user) and video.get('uploader_id') == g.user['id']


def get_role(user, data):
    if not user:
        return None
    if user['id'] == OWNER_ID:
        return 'owner'
    entry = data['users'].get(user['id'])
    return entry['role'] if entry else None


def get_upload_state(user, role, data):
    """'logged_out', 'banned', 'restricted' or 'allowed'."""
    if not user:
        return 'logged_out'
    if role == 'owner':
        return 'allowed'
    if user['id'] in data['banned']:
        return 'banned'
    if role is not None or data['open_uploads']:
        return 'allowed'
    return 'restricted'


sync_videos()

MAINTENANCE_OPEN_ENDPOINTS = {'login', 'callback', 'logout', 'static'}


@app.before_request
def load_request_state():
    g.data = load_data()
    g.user = session.get('user')
    g.role = get_role(g.user, g.data)
    g.is_staff = g.role in ('owner', 'mod')
    g.upload_state = get_upload_state(g.user, g.role, g.data)
    g.can_upload = g.upload_state == 'allowed'
    g.ban_reason = (g.data['banned'].get(g.user['id'], {}).get('reason', '')
                    if g.user else '')

    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    if request.method == 'POST':
        token = request.form.get('csrf_token', '')
        if not secrets.compare_digest(token, session['csrf']):
            abort(400)

    if (g.data['maintenance'] and not g.is_staff
            and request.endpoint not in MAINTENANCE_OPEN_ENDPOINTS):
        if wants_json():
            return jsonify(ok=False, error='The site is under maintenance right now.'), 503
        return render_template('maintenance.html'), 503


@app.context_processor
def inject_globals():
    return {
        'site_name': SITE_NAME,
        'csrf_token': session.get('csrf', ''),
        'user': session.get('user'),
        'is_staff': getattr(g, 'is_staff', False),
        'can_upload': getattr(g, 'can_upload', False),
        'upload_state': getattr(g, 'upload_state', 'logged_out'),
        'ban_reason': getattr(g, 'ban_reason', ''),
        'max_upload_mb': MAX_UPLOAD_MB,
        'maintenance': getattr(g, 'data', {}).get('maintenance', False),
    }


def staff_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not g.user:
            return redirect(url_for('login'))
        if not g.is_staff:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def owner_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not g.user:
            return redirect(url_for('login'))
        if g.role != 'owner':
            abort(403)
        return view(*args, **kwargs)
    return wrapper


# -------------------------------------------------------------------- public
@app.route('/')
def index():
    videos = all_videos()
    return render_template(
        'index.html',
        video=videos[0] if videos else None,
        recent=videos[1:7],
    )


@app.route('/videos/<int:video_id>')
def view_video(video_id):
    raw = g.data['videos'].get(str(video_id))
    if not raw:
        abort(404)
    video = decorate(raw)
    ids = sorted(int(k) for k in g.data['videos'])
    return render_template(
        'video.html',
        video=video,
        newer_id=next((i for i in ids if i > video_id), None),
        older_id=next((i for i in reversed(ids) if i < video_id), None),
        is_latest=(video_id == ids[-1]),
        can_delete=can_delete(video),
    )


@app.route('/my-videos')
def my_videos():
    if not g.user:
        return redirect(url_for('login'))
    mine = [v for v in all_videos() if v.get('uploader_id') == g.user['id']]
    return render_template('my_videos.html', videos=mine)


@app.route('/videos/<int:video_id>/delete', methods=['POST'])
def delete_video(video_id):
    if not g.user:
        return redirect(url_for('login'))

    targets = {'admin': 'admin', 'mine': 'my_videos'}
    destination = url_for(targets.get(request.form.get('next'), 'index'))

    raw = g.data['videos'].get(str(video_id))
    if not raw:
        flash('That video no longer exists.', 'error')
        return redirect(destination)
    if not can_delete(raw):
        abort(403)

    try:
        os.remove(os.path.join(UPLOAD_FOLDER, raw['filename']))
    except OSError:
        pass
    modify_data(lambda d: d['videos'].pop(str(video_id), None))
    flash('Video deleted.', 'success')
    return redirect(destination)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        return render_template('upload.html')

    def fail(message, status):
        if wants_json():
            return jsonify(ok=False, error=message), status
        flash(message, 'error')
        return redirect(url_for('upload_file'))

    if not g.user:
        return fail('Log in with Discord before uploading a video.', 401)
    if g.upload_state == 'banned':
        reason = f' Reason: {g.ban_reason}' if g.ban_reason else ''
        return fail('Your account is banned from uploading.' + reason, 403)
    if not g.can_upload:
        return fail('Your account is not allowed to upload videos.', 403)

    file = request.files.get('video')
    if not file or file.filename == '':
        return fail('Choose a video file to upload.', 400)
    if not allowed_file(file.filename):
        return fail('Use an MP4, WebM, or Ogg video file.', 400)

    original_name = secure_filename(file.filename)
    if not original_name:
        return fail('That filename is not valid.', 400)

    filename = f'{secrets.token_hex(8)}_{original_name}'
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)

    title = (request.form.get('title', '').strip()[:80]
             or os.path.splitext(original_name)[0].replace('_', ' ')[:80]
             or 'Untitled')
    result = {}

    def change(data):
        vid = data['next_video_id']
        data['next_video_id'] = vid + 1
        data['videos'][str(vid)] = {
            'id': vid,
            'filename': filename,
            'title': title,
            'uploader_id': g.user['id'],
            'uploader_name': g.user['username'],
            'uploaded_at': datetime.now().isoformat(),
            'size': os.path.getsize(path),
        }
        result['id'] = vid

    modify_data(change)
    flash('Your video is uploaded and ready to play.', 'success')
    target = url_for('view_video', video_id=result['id'])
    if wants_json():
        return jsonify(ok=True, redirect=target)
    return redirect(target)


# --------------------------------------------------------------------- login
@app.route('/login')
def login():
    if not CLIENT_ID:
        flash('Discord login is not configured yet. Set DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET.', 'error')
        return redirect(url_for('index'))

    state = secrets.token_urlsafe(24)
    session['oauth_state'] = state
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'identify',
        'state': state,
    }
    return redirect(f'{DISCORD_AUTHORIZE_URL}?{urlencode(params)}')


@app.route('/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')
    if not code or not state or state != session.pop('oauth_state', None):
        flash('Discord sign-in could not be verified. Please try again.', 'error')
        return redirect(url_for('index'))

    if not CLIENT_ID or not CLIENT_SECRET:
        flash('Discord login is not configured yet.', 'error')
        return redirect(url_for('index'))

    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        token_response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers, timeout=10)
        token_response.raise_for_status()
        token_json = token_response.json()
    except (requests.RequestException, ValueError):
        flash('Discord sign-in failed while exchanging the authorization code.', 'error')
        return redirect(url_for('index'))

    if 'access_token' not in token_json:
        flash('Discord did not return an access token.', 'error')
        return redirect(url_for('index'))

    user_headers = {'Authorization': f"Bearer {token_json['access_token']}"}
    try:
        user_response = requests.get(DISCORD_USER_URL, headers=user_headers, timeout=10)
        user_response.raise_for_status()
        user_data = user_response.json()
    except (requests.RequestException, ValueError):
        flash('Could not retrieve your Discord profile.', 'error')
        return redirect(url_for('index'))

    session['user'] = {
        'username': user_data.get('global_name') or user_data['username'],
        'avatar': user_data.get('avatar'),
        'id': user_data['id'],
    }
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


# --------------------------------------------------------------------- admin
@app.route('/admin')
@staff_required
def admin():
    sync_videos()
    g.data = load_data()
    videos = all_videos()
    banned_ids = set(g.data['banned'])
    users = sorted(
        ({'id': uid, 'banned': uid in banned_ids, **info} for uid, info in g.data['users'].items()),
        key=lambda u: (u['role'] != 'mod', u['id']),
    )
    bans = sorted(({'id': uid, **info} for uid, info in g.data['banned'].items()),
                  key=lambda b: b['id'])
    stats = {
        'videos': len(videos),
        'size_mb': round(sum(v.get('size', 0) for v in g.data['videos'].values()) / (1024 * 1024), 1),
        'people': len(users) + 1,
    }
    return render_template(
        'admin.html',
        role=g.role,
        videos=videos,
        users=users,
        bans=bans,
        stats=stats,
        open_uploads=g.data['open_uploads'],
        owner_id=OWNER_ID,
    )


@app.route('/admin/maintenance', methods=['POST'])
@staff_required
def admin_maintenance():
    enabled = request.form.get('enabled') == '1'
    modify_data(lambda d: d.update(maintenance=enabled))
    flash('Maintenance mode is ON. Visitors will see the maintenance page.' if enabled
          else 'Maintenance mode is OFF. The site is live.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/open-uploads', methods=['POST'])
@owner_required
def admin_open_uploads():
    enabled = request.form.get('enabled') == '1'
    modify_data(lambda d: d.update(open_uploads=enabled))
    flash('Any logged-in user can now upload.' if enabled
          else 'Only approved people can upload.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/users/add', methods=['POST'])
@owner_required
def admin_add_user():
    user_id = request.form.get('user_id', '').strip()
    role = request.form.get('role', '')
    label = request.form.get('label', '').strip()[:40]

    if not re.fullmatch(r'\d{17,20}', user_id):
        flash('That is not a valid Discord ID. It should be 17 to 20 digits.', 'error')
    elif user_id == OWNER_ID:
        flash('That ID is already the owner.', 'error')
    elif role not in ('uploader', 'mod'):
        flash('Choose a role.', 'error')
    else:
        def change(data):
            data['users'][user_id] = {'role': role, 'label': label}
        modify_data(change)
        flash(f'Added {label or user_id} as {role}.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/users/remove', methods=['POST'])
@owner_required
def admin_remove_user():
    user_id = request.form.get('user_id', '')
    modify_data(lambda d: d['users'].pop(user_id, None))
    flash('Person removed.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/bans/add', methods=['POST'])
@staff_required
def admin_ban_add():
    user_id = request.form.get('user_id', '').strip()
    reason = request.form.get('reason', '').strip()[:120]
    target = g.data['users'].get(user_id, {})

    if not re.fullmatch(r'\d{17,20}', user_id):
        flash('That is not a valid Discord ID. It should be 17 to 20 digits.', 'error')
    elif user_id == OWNER_ID:
        flash("The owner can't be banned.", 'error')
    elif user_id == g.user['id']:
        flash("You can't ban yourself.", 'error')
    elif target.get('role') == 'mod' and g.role != 'owner':
        flash('Only the owner can ban a mod.', 'error')
    else:
        name = (next((v['uploader_name'] for v in g.data['videos'].values()
                      if v.get('uploader_id') == user_id), '')
                or target.get('label', ''))

        def change(data):
            data['banned'][user_id] = {
                'reason': reason,
                'name': name,
                'at': datetime.now().strftime('%b %d, %Y'),
            }
        modify_data(change)
        flash(f'{name or user_id} is now banned from uploading.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/bans/remove', methods=['POST'])
@staff_required
def admin_ban_remove():
    user_id = request.form.get('user_id', '')
    modify_data(lambda d: d['banned'].pop(user_id, None))
    flash('Ban removed. They can upload again if they have permission.', 'success')
    return redirect(url_for('admin'))


# ------------------------------------------------------------ error handlers
@app.errorhandler(413)
def upload_too_large(_error):
    message = f'The video is too large. The maximum upload size is {MAX_UPLOAD_MB} MB.'
    if wants_json():
        return jsonify(ok=False, error=message), 413
    flash(message, 'error')
    return redirect(url_for('upload_file'))


@app.errorhandler(400)
def bad_request(_error):
    if wants_json():
        return jsonify(ok=False, error='Your session expired. Refresh the page and try again.'), 400
    flash('That request could not be verified. Please try again.', 'error')
    return redirect(url_for('index'))


@app.errorhandler(403)
def forbidden(_error):
    if wants_json():
        return jsonify(ok=False, error="You don't have access to that."), 403
    flash("You don't have access to that page.", 'error')
    return redirect(url_for('index'))


@app.errorhandler(404)
def not_found(_error):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(port=5000, debug=os.environ.get('FLASK_DEBUG') == '1')
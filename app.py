from flask import Flask, request, send_file, render_template, redirect, url_for, flash, session
import os
import logging
import sqlite3
import secrets
import re
import tempfile
import time
import smtplib
import ssl
import traceback
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from converter import convert_file_input

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
UPLOAD_FOLDER = 'Uploads'
OUTPUT_FOLDER = 'outputs'
DATABASE = 'users.db'

# Logging setup
log_file = '/var/www/flask-app/app.log' if os.path.exists('/var/www/flask-app') else os.path.join(
    os.path.dirname(__file__), 'app.log')
logging.basicConfig(
    level=logging.DEBUG,
    filename=log_file,
    format='%(asctime)s %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)
logger.debug("Starting Flask app")

# Ensure directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Supported conversions
SUPPORTED_CONVERSIONS = {
    'ttf': ['ttf', 'otf', 'woff', 'woff2'],
    'otf': ['ttf', 'otf', 'woff', 'woff2'],
    'woff': ['ttf', 'otf', 'woff', 'woff2'],
    'woff2': ['ttf', 'otf', 'woff', 'woff2'],
    'png': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'jpg': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'jpeg': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'gif': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'bmp': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'tiff': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'webp': ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'pdf'],
    'pdf': ['png', 'jpg', 'jpeg', 'docx', 'txt'],
    'docx': ['docx', 'pdf', 'txt'],
    'txt': ['pdf', 'docx', 'md'],
    'odt': ['docx', 'txt'],
    'md': ['pdf', 'txt'],
    'mp3': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'wav': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'ogg': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'flac': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'aac': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'm4a': ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
    'mp4': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'avi': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'mkv': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'mov': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'wmv': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'flv': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'webm': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
    'zip': ['zip', 'tar', 'gz', '7z'],
    'tar': ['zip', 'tar', 'gz', '7z'],
    'gz': ['zip', 'tar', 'gz', '7z'],
    '7z': ['zip', 'tar', 'gz', '7z'],
    'csv': ['csv', 'xls', 'xlsx', 'json', 'txt'],
    'xls': ['csv', 'xls', 'xlsx', 'json', 'txt'],
    'xlsx': ['csv', 'xls', 'xlsx', 'json', 'txt'],
    'json': ['csv', 'txt'],
    'xml': ['json', 'txt'],
}


# Database initialization
def init_db():
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if not cursor.fetchone():
                conn.execute('''
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT,
                        password TEXT NOT NULL,
                        is_admin INTEGER DEFAULT 0,
                        is_verified INTEGER DEFAULT 1,
                        credits INTEGER DEFAULT 10
                    )
                ''')
                hashed_password = generate_password_hash('admin')
                conn.execute(
                    'INSERT INTO users (username, password, is_admin, is_verified, credits) VALUES (?, ?, ?, ?, ?)',
                    ('admin', hashed_password, 1, 1, 10))
                logger.debug("Created admin user with no email")
            else:
                conn.execute('UPDATE users SET email = NULL WHERE username = "admin"')

            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
            if not cursor.fetchone():
                conn.execute('''
                    CREATE TABLE settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mb_per_credit REAL DEFAULT 1.0,
                        usd_per_credit REAL DEFAULT 0.01
                    )
                ''')
                conn.execute('INSERT INTO settings (mb_per_credit, usd_per_credit) VALUES (?, ?)', (1.0, 0.01))
                logger.debug("Created settings table")
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database init failed: {e}")
        raise


# Conversion rates
def get_conversion_rates():
    try:
        with sqlite3.connect(DATABASE) as conn:
            settings = conn.execute('SELECT mb_per_credit, usd_per_credit FROM settings WHERE id = 1').fetchone()
            return settings if settings else (1.0, 0.01)
    except sqlite3.Error as e:
        logger.error(f"Error fetching rates: {e}")
        return (1.0, 0.01)


# Check if user is admin
def get_user_is_admin(user_id):
    try:
        with sqlite3.connect(DATABASE) as conn:
            result = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
            return bool(result[0]) if result else False
    except sqlite3.Error as e:
        logger.error(f"Error checking admin: {e}")
        return False


app.jinja_env.globals.update(get_user_is_admin=get_user_is_admin)


# Login required decorator
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    wrap.__name__ = f.__name__
    return wrap


# Admin required decorator
def admin_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in.')
            return redirect(url_for('login'))
        if not get_user_is_admin(session['user_id']):
            flash('Admin access required.')
            return redirect(url_for('upload_file'))
        return f(*args, **kwargs)

    wrap.__name__ = f.__name__
    return wrap


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if not username or not email or not password:
            flash('All fields are required.')
            return redirect(url_for('register'))

        if not re.match(r'^[a-zA-Z0-9._%+-]+@gmail\.com$', email):
            flash('Email is invalid. Only Gmail addresses are allowed.')
            return redirect(url_for('register'))

        try:
            with sqlite3.connect(DATABASE) as conn:
                existing_email = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
                existing_username = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
                if existing_email:
                    flash('Email is already in use.')
                    return redirect(url_for('register'))
                if existing_username:
                    flash('Username already exists.')
                    return redirect(url_for('register'))
        except sqlite3.Error as e:
            logger.error(f"Registration check error: {e}")
            flash('Registration failed.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.execute(
                    'INSERT INTO users (username, email, password, is_verified, credits) VALUES (?, ?, ?, ?, ?)',
                    (username, email, hashed_password, 1, 10))
                conn.commit()
            logger.debug(f"User registered: {username}, {email}")
        except sqlite3.Error as e:
            logger.error(f"Register error: {e}")
            flash('Registration failed.')
            return redirect(url_for('register'))

        # Send welcome email using smtplib
        email_sender = 'fconvertz@gmail.com'
        email_password = 'amddpfhiwyrmvdjb'  # New App Password
        subject = 'Welcome to FileConvertz'
        body = f'Hello {username},\n\nYour account has been successfully created. You can now log in and start converting files.\n\nBest,\nFileConvertz Team'

        em = EmailMessage()
        em['From'] = email_sender
        em['To'] = email
        em['Subject'] = subject
        em.set_content(body)

        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            logger.debug(f"Attempting to send email to {email}")
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context, timeout=10) as smtp:
                smtp.set_debuglevel(1)
                smtp.login(email_sender, email_password)
                smtp.sendmail(email_sender, email, em.as_string())
            logger.debug(f"Sent email to {email}")
            flash('Registration successful! A welcome email has been sent.')
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"Email authentication failed: {str(e)}\n{traceback.format_exc()}")
            flash(f'Registration successful, but email sending failed: Authentication error - {str(e)}')
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {str(e)}\n{traceback.format_exc()}")
            flash(f'Registration successful, but email sending failed: SMTP error - {str(e)}')
        except Exception as e:
            logger.error(f"Unexpected email error: {str(e)}\n{traceback.format_exc()}")
            flash(f'Registration successful, but email sending failed: Unexpected error - {str(e)}')

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            with sqlite3.connect(DATABASE) as conn:
                user = conn.execute('SELECT id, password, is_admin FROM users WHERE username = ?',
                                    (username,)).fetchone()
            if not user:
                flash('Username not found.')
            elif user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                logger.debug(f"User logged in: {username}")
                flash('Logged in!')
                return redirect(url_for('admin_dashboard') if user[2] else url_for('upload_file'))
            else:
                flash('Invalid password.')
        except sqlite3.Error as e:
            logger.error(f"Login error: {e}")
            flash('Login failed.')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out.')
    return redirect(url_for('login'))


@app.route('/account')
@login_required
def account():
    try:
        with sqlite3.connect(DATABASE) as conn:
            user = conn.execute('SELECT username, email, credits FROM users WHERE id = ?',
                                (session['user_id'],)).fetchone()
        if user:
            return render_template('account.html', username=user[0], email=user[1] or 'No email', credits=user[2])
        flash('User not found.')
        return redirect(url_for('login'))
    except sqlite3.Error as e:
        logger.error(f"Account error: {e}")
        flash('Error fetching account.')
        return redirect(url_for('upload_file'))


@app.route('/', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            logger.error("No file uploaded")
            flash('No file uploaded.')
            return redirect(url_for('upload_file'))
        file = request.files['file']
        if file.filename == '':
            logger.error("No file selected")
            flash('No file selected.')
            return redirect(url_for('upload_file'))

        file.seek(0, os.SEEK_END)
        file_size_mb = file.tell() / (1024 * 1024)
        file.seek(0)
        if file_size_mb > 100:
            flash('File too large (max 100 MB).')
            return redirect(url_for('upload_file'))

        input_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        output_format = request.form.get('output_format', '').lower()
        if not output_format or input_ext not in SUPPORTED_CONVERSIONS or output_format not in SUPPORTED_CONVERSIONS.get(
                input_ext, []):
            flash('Unsupported conversion.')
            return redirect(url_for('upload_file'))

        mb_per_credit, _ = get_conversion_rates()
        required_credits = max(1, int(file_size_mb / mb_per_credit))

        try:
            with sqlite3.connect(DATABASE) as conn:
                user_credits = conn.execute('SELECT credits FROM users WHERE id = ?',
                                            (session['user_id'],)).fetchone()
                if not user_credits:
                    flash('User not found.')
                    return redirect(url_for('upload_file'))
                user_credits = user_credits[0]
                if user_credits < required_credits:
                    flash(f'Not enough credits. Need: {required_credits}, Have: {user_credits}')
                    return redirect(url_for('upload_file'))
        except sqlite3.Error as e:
            logger.error(f"Credit check error: {e}")
            flash('Error checking credits.')
            return redirect(url_for('upload_file'))

        safe_filename = ''.join(c for c in file.filename if c.isalnum() or c in ('.', '_', '-'))
        input_fd, input_path = tempfile.mkstemp(suffix=f'.{input_ext}', dir=UPLOAD_FOLDER)
        base_filename = os.path.splitext(safe_filename)[0]
        output_path = os.path.join(OUTPUT_FOLDER, f"{base_filename}.{output_format}")

        try:
            with os.fdopen(input_fd, 'wb') as f:
                file.save(f)
            logger.debug(f"Saved input file: {input_path}")

            logger.debug(f"Starting conversion: {input_path} to {output_path} ({input_ext} -> {output_format})")
            success = convert_file_input(input_path, output_path, input_ext, output_format)
            if not success:
                logger.error(f"Conversion failed for {input_path} to {output_path}")
                flash('Conversion failed.')
                return redirect(url_for('upload_file'))

            actual_output_path = output_path
            if input_ext == 'pdf' and output_format in ['png', 'jpg', 'jpeg']:
                zip_path = os.path.join(OUTPUT_FOLDER, f"{base_filename}.zip")
                if os.path.exists(zip_path):
                    actual_output_path = zip_path
                    logger.debug(f"Multi-page PDF detected, serving ZIP: {actual_output_path}")
                elif not os.path.exists(actual_output_path):
                    logger.error(f"Output file not found at {actual_output_path} or {zip_path}")
                    flash('Conversion succeeded but output file is missing.')
                    return redirect(url_for('upload_file'))

            try:
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute('UPDATE users SET credits = credits - ? WHERE id = ?',
                                 (required_credits, session['user_id']))
                    conn.commit()
                logger.debug(f"Deducted {required_credits} credits for user {session['user_id']}")
                response = send_file(actual_output_path, as_attachment=True,
                                     download_name=os.path.basename(actual_output_path))
                return response
            except sqlite3.Error as e:
                logger.error(f"Credit deduction error: {e}")
                flash(f'Conversion succeeded but failed to update credits: {str(e)}')
                return redirect(url_for('upload_file'))
        except Exception as e:
            logger.error(f"Conversion error: {str(e)}")
            flash(f'Error during conversion: {str(e)}')
            return redirect(url_for('upload_file'))
        finally:
            for _ in range(3):  # Retry cleanup
                try:
                    if os.path.exists(input_path):
                        os.remove(input_path)
                        logger.debug(f"Cleaned up input file: {input_path}")
                    if os.path.exists(output_path) and output_path != actual_output_path:
                        os.remove(output_path)
                        logger.debug(f"Cleaned up output file: {output_path}")
                    if actual_output_path != output_path and os.path.exists(actual_output_path):
                        os.remove(actual_output_path)
                        logger.debug(f"Cleaned up actual output file: {actual_output_path}")
                    break
                except PermissionError as e:
                    logger.warning(f"PermissionError during cleanup, retrying: {e}")
                    time.sleep(1)
                except Exception as e:
                    logger.error(f"Cleanup error: {e}")
                    break
    return render_template('index.html', output_options=SUPPORTED_CONVERSIONS)


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            with sqlite3.connect(DATABASE) as conn:
                if action == 'update_admin':
                    new_username = request.form.get('new_username', '').strip()
                    new_password = request.form.get('new_password', '').strip()

                    if not new_username or not new_password:
                        flash('Both username and password are required.')
                        return redirect(url_for('admin_dashboard'))

                    existing_username = conn.execute('SELECT id FROM users WHERE username = ? AND id != ?',
                                                     (new_username, session['user_id'])).fetchone()
                    if existing_username:
                        flash('Username already exists.')
                        return redirect(url_for('admin_dashboard'))

                    hashed_password = generate_password_hash(new_password)
                    conn.execute('UPDATE users SET username = ?, password = ? WHERE id = ?',
                                 (new_username, hashed_password, session['user_id']))
                    conn.commit()
                    logger.debug(f"Admin updated: username={new_username}")
                    flash('Admin credentials updated.')

                elif action == 'remove_user':
                    user_id = request.form['user_id']
                    conn.execute('DELETE FROM users WHERE id = ? AND is_admin = 0', (user_id,))
                    conn.commit()
                    logger.debug(f"User removed: {user_id}")
                    flash('User removed.')

                elif action == 'update_credits':
                    user_id = request.form['user_id']
                    credits = request.form['credits']
                    try:
                        credits = int(credits)
                        if credits < 0:
                            flash('Credits cannot be negative.')
                            return redirect(url_for('admin_dashboard'))
                        conn.execute('UPDATE users SET credits = ? WHERE id = ? AND is_admin = 0',
                                     (credits, user_id))
                        conn.commit()
                        logger.debug(f"Credits updated for user {user_id}: {credits}")
                        flash('Credits updated.')
                    except ValueError:
                        flash('Credits must be a valid number.')

                elif action == 'update_rates':
                    mb_per_credit = request.form['mb_per_credit']
                    usd_per_credit = request.form['usd_per_credit']
                    try:
                        mb_per_credit = float(mb_per_credit)
                        usd_per_credit = float(usd_per_credit)
                        if mb_per_credit <= 0 or usd_per_credit <= 0:
                            flash('Rates must be positive.')
                            return redirect(url_for('admin_dashboard'))
                        conn.execute('UPDATE settings SET mb_per_credit = ?, usd_per_credit = ? WHERE id = 1',
                                     (mb_per_credit, usd_per_credit))
                        conn.commit()
                        logger.debug(f"Rates updated: mb_per_credit={mb_per_credit}, usd_per_credit={usd_per_credit}")
                        flash('Rates updated.')
                    except ValueError:
                        flash('Rates must be valid numbers.')

                elif action == 'search_users':
                    search_query = request.form['search_query'].strip()
                    users = conn.execute(
                        'SELECT id, username, credits FROM users WHERE is_admin = 0 AND username LIKE ?',
                        (f'%{search_query}%',)).fetchall()
                    mb_per_credit, usd_per_credit = get_conversion_rates()
                    return render_template('admin.html', users=users, search_query=search_query,
                                           mb_per_credit=mb_per_credit, usd_per_credit=usd_per_credit)
        except sqlite3.Error as e:
            logger.error(f"Admin action error: {e}")
            flash(f'Action failed: {str(e)}')

    try:
        with sqlite3.connect(DATABASE) as conn:
            users = conn.execute('SELECT id, username, credits FROM users WHERE is_admin = 0').fetchall()
        mb_per_credit, usd_per_credit = get_conversion_rates()
    except sqlite3.Error as e:
        logger.error(f"Admin fetch error: {e}")
        users = []
        mb_per_credit, usd_per_credit = 1.0, 0.01
    return render_template('admin.html', users=users, search_query='',
                           mb_per_credit=mb_per_credit, usd_per_credit=usd_per_credit)


with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True)

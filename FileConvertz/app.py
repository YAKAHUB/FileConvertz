from flask import Flask, request, send_file, render_template, redirect, url_for, flash, session
import os
import logging
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from converter import convert_file_input

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure random key in production
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
DATABASE = 'users.db'

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Supported conversions mapping (only natively supported by converter.py)
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

# Helper function to check if a user is an admin
def get_user_is_admin(user_id):
    try:
        with sqlite3.connect(DATABASE) as conn:
            result = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
            return bool(result[0]) if result else False
    except sqlite3.Error as e:
        logger.error(f"Error checking admin status: {str(e)}")
        return False

# Register helper function with Jinja2
app.jinja_env.globals.update(get_user_is_admin=get_user_is_admin)

# Database initialization with credits and settings
def init_db():
    try:
        with sqlite3.connect(DATABASE) as conn:
            # Check if users table exists
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            users_table_exists = cursor.fetchone() is not None

            if not users_table_exists:
                # Create users table only if it doesn't exist
                conn.execute('''
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        is_admin INTEGER DEFAULT 0,
                        credits INTEGER DEFAULT 10
                    )
                ''')
                # Insert default admin user
                hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')
                conn.execute('INSERT INTO users (username, password, is_admin, credits) VALUES (?, ?, ?, ?)',
                             ('admin', hashed_password, 1, 10))
                logger.debug("Admin user 'admin' created with password 'admin'.")
            else:
                logger.debug("Users table already exists, skipping admin creation.")

            # Check if settings table exists
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'")
            settings_table_exists = cursor.fetchone() is not None

            if not settings_table_exists:
                # Create settings table only if it doesn't exist
                conn.execute('''
                    CREATE TABLE settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mb_per_credit REAL DEFAULT 1.0,  -- MB per credit
                        usd_per_credit REAL DEFAULT 0.01  -- USD per credit
                    )
                ''')
                conn.execute('INSERT INTO settings (mb_per_credit, usd_per_credit) VALUES (?, ?)', (1.0, 0.01))
                logger.debug("Settings table created with default values.")
            else:
                logger.debug("Settings table already exists, skipping initialization.")

            conn.commit()
        logger.debug("Database initialization completed.")
    except sqlite3.Error as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

# Helper function to get credit conversion rates
def get_conversion_rates():
    try:
        with sqlite3.connect(DATABASE) as conn:
            settings = conn.execute('SELECT mb_per_credit, usd_per_credit FROM settings WHERE id = 1').fetchone()
            return settings if settings else (1.0, 0.01)  # Default values: 1 MB = 1 credit, 1 credit = $0.01
    except sqlite3.Error as e:
        logger.error(f"Error fetching conversion rates: {str(e)}")
        return (1.0, 0.01)  # Fallback defaults

# Login required decorator
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# Admin required decorator
def admin_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        with sqlite3.connect(DATABASE) as conn:
            user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or not user[0]:
            flash('Admin access required.')
            return redirect(url_for('upload_file'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.execute('INSERT INTO users (username, password, credits) VALUES (?, ?, ?)',
                             (username, hashed_password, 10))
                conn.commit()
            logger.debug(f"User {username} registered successfully with 10 credits.")
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            logger.debug(f"Registration failed: Username {username} already exists.")
            flash('Username already exists.')
            return redirect(url_for('register'))
        except sqlite3.Error as e:
            logger.error(f"Database error during registration: {str(e)}")
            flash('An error occurred during registration. Please try again.')
            return redirect(url_for('register'))

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
        except sqlite3.Error as e:
            logger.error(f"Database error during login: {str(e)}")
            flash('An error occurred. Please try again.')
            return redirect(url_for('login'))

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            logger.debug(f"User {username} logged in successfully.")
            flash('Logged in successfully!')
            if user[2]:  # Check if is_admin is 1 (admin user)
                logger.debug(f"Admin user {username} redirected to admin dashboard.")
                return redirect(url_for('admin_dashboard'))  # Redirect admin to dashboard
            return redirect(url_for('upload_file'))  # Non-admin to upload page
        else:
            logger.debug(f"Login failed for user {username}: Invalid credentials.")
            flash('Invalid username or password.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    logger.debug("User logged out.")
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/account', methods=['GET'])
@login_required
def account():
    try:
        with sqlite3.connect(DATABASE) as conn:
            user = conn.execute('SELECT username, credits FROM users WHERE id = ?',
                                (session['user_id'],)).fetchone()
        if user:
            return render_template('account.html', username=user[0], credits=user[1])
        else:
            flash('User not found.')
            return redirect(url_for('login'))
    except sqlite3.Error as e:
        logger.error(f"Database error fetching account info: {str(e)}")
        flash('An error occurred. Please try again.')
        return redirect(url_for('upload_file'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                logger.error("No file uploaded")
                return "No file uploaded", 400
            file = request.files['file']
            if file.filename == '':
                logger.error("No file selected")
                return "No file selected", 400

            input_path = os.path.join(UPLOAD_FOLDER, file.filename)
            logger.debug(f"Saving uploaded file to {input_path}")
            file.save(input_path)
            if not os.path.exists(input_path):
                logger.error(f"Failed to save file to {input_path}")
                return "Failed to save uploaded file", 500

            # Calculate file size in MB and required credits
            file_size_mb = os.path.getsize(input_path) / (1024 * 1024)  # Convert bytes to MB
            mb_per_credit, _ = get_conversion_rates()
            required_credits = max(1, int(file_size_mb / mb_per_credit) + (1 if file_size_mb % mb_per_credit > 0 else 0))  # Round up to next credit

            # Check user's credits
            with sqlite3.connect(DATABASE) as conn:
                user_credits = conn.execute('SELECT credits FROM users WHERE id = ?',
                                            (session['user_id'],)).fetchone()[0]
            if user_credits < required_credits:
                os.remove(input_path)
                flash(f"Not enough credits. Required: {required_credits}, Available: {user_credits}")
                return redirect(url_for('upload_file'))

            output_format = request.form['output_format']
            base_filename = os.path.splitext(file.filename)[0]
            output_path = os.path.join(OUTPUT_FOLDER, f"{base_filename}.{output_format}")
            logger.debug(f"Output path set to {output_path}")

            input_ext = os.path.splitext(file.filename)[1][1:].lower()
            success = convert_file_input(input_path, output_path, input_ext, output_format)

            if not success:
                logger.error("Conversion failed")
                os.remove(input_path)
                return "Conversion failed. Check server logs for details.", 500

            actual_output_path = output_path
            if input_ext == 'pdf' and output_format in ['png', 'jpg', 'jpeg']:
                zip_path = os.path.join(OUTPUT_FOLDER, f"{base_filename}.zip")
                if os.path.exists(zip_path):
                    actual_output_path = zip_path
                    logger.debug(f"Multi-page PDF detected, serving ZIP: {actual_output_path}")
                elif not os.path.exists(actual_output_path):
                    logger.error(f"Output file not found at {actual_output_path} or {zip_path}")
                    os.remove(input_path)
                    return "Output file not generated", 500

            # Deduct credits only if file is successfully served
            with sqlite3.connect(DATABASE) as conn:
                conn.execute('UPDATE users SET credits = credits - ? WHERE id = ?',
                             (required_credits, session['user_id']))
                conn.commit()
            logger.debug(f"Deducted {required_credits} credits for user ID {session['user_id']}")

            os.remove(input_path)
            logger.debug(f"Serving file: {actual_output_path}")
            return send_file(actual_output_path, as_attachment=True, download_name=os.path.basename(actual_output_path))

        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            if os.path.exists(input_path):
                os.remove(input_path)
            return f"An unexpected error occurred: {str(e)}", 500

    return render_template('index.html', output_options=SUPPORTED_CONVERSIONS)

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_admin':
            new_username = request.form['new_username']
            new_password = request.form['new_password']
            if not new_username or not new_password:
                flash('New username and password are required.')
                return redirect(url_for('admin_dashboard'))
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            try:
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute('UPDATE users SET username = ?, password = ? WHERE id = ?',
                                 (new_username, hashed_password, session['user_id']))
                    conn.commit()
                logger.debug(f"Admin updated credentials to username: {new_username}")
                flash('Admin credentials updated successfully.')
                return redirect(url_for('admin_dashboard'))
            except sqlite3.IntegrityError:
                flash('Username already exists.')
                return redirect(url_for('admin_dashboard'))
            except sqlite3.Error as e:
                logger.error(f"Database error updating admin: {str(e)}")
                flash('An error occurred. Please try again.')
                return redirect(url_for('admin_dashboard'))

        elif action == 'remove_user':
            user_id = request.form['user_id']
            try:
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute('DELETE FROM users WHERE id = ? AND is_admin = 0', (user_id,))
                    conn.commit()
                logger.debug(f"Admin removed user with ID: {user_id}")
                flash('User removed successfully.')
                return redirect(url_for('admin_dashboard'))
            except sqlite3.Error as e:
                logger.error(f"Database error removing user: {str(e)}")
                flash('An error occurred. Please try again.')
                return redirect(url_for('admin_dashboard'))

        elif action == 'update_credits':
            user_id = request.form['user_id']
            credits = request.form['credits']
            try:
                credits = int(credits)
                if credits < 0:
                    flash('Credits cannot be negative.')
                    return redirect(url_for('admin_dashboard'))
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute('UPDATE users SET credits = ? WHERE id = ? AND is_admin = 0',
                                 (credits, user_id))
                    conn.commit()
                logger.debug(f"Admin updated credits for user ID {user_id} to {credits}")
                flash('User credits updated successfully.')
                return redirect(url_for('admin_dashboard'))
            except ValueError:
                flash('Credits must be a valid number.')
                return redirect(url_for('admin_dashboard'))
            except sqlite3.Error as e:
                logger.error(f"Database error updating credits: {str(e)}")
                flash('An error occurred. Please try again.')
                return redirect(url_for('admin_dashboard'))

        elif action == 'update_rates':
            mb_per_credit = request.form['mb_per_credit']
            usd_per_credit = request.form['usd_per_credit']
            try:
                mb_per_credit = float(mb_per_credit)
                usd_per_credit = float(usd_per_credit)
                if mb_per_credit <= 0 or usd_per_credit <= 0:
                    flash('Rates must be positive numbers.')
                    return redirect(url_for('admin_dashboard'))
                with sqlite3.connect(DATABASE) as conn:
                    conn.execute('UPDATE settings SET mb_per_credit = ?, usd_per_credit = ? WHERE id = 1',
                                 (mb_per_credit, usd_per_credit))
                    conn.commit()
                logger.debug(f"Admin updated rates: {mb_per_credit} MB/credit, ${usd_per_credit}/credit")
                flash('Conversion rates updated successfully.')
                return redirect(url_for('admin_dashboard'))
            except ValueError:
                flash('Rates must be valid numbers.')
                return redirect(url_for('admin_dashboard'))
            except sqlite3.Error as e:
                logger.error(f"Database error updating rates: {str(e)}")
                flash('An error occurred. Please try again.')
                return redirect(url_for('admin_dashboard'))

        elif action == 'search_users':
            search_query = request.form['search_query'].strip()
            try:
                with sqlite3.connect(DATABASE) as conn:
                    users = conn.execute('SELECT id, username, credits FROM users WHERE is_admin = 0 AND username LIKE ?',
                                         (f'%{search_query}%',)).fetchall()
            except sqlite3.Error as e:
                logger.error(f"Database error searching users: {str(e)}")
                flash('Error searching users.')
                users = []
            mb_per_credit, usd_per_credit = get_conversion_rates()
            return render_template('admin.html', users=users, search_query=search_query,
                                   mb_per_credit=mb_per_credit, usd_per_credit=usd_per_credit)

    # Fetch all non-admin users and conversion rates by default
    try:
        with sqlite3.connect(DATABASE) as conn:
            users = conn.execute('SELECT id, username, credits FROM users WHERE is_admin = 0').fetchall()
        mb_per_credit, usd_per_credit = get_conversion_rates()
    except sqlite3.Error as e:
        logger.error(f"Database error fetching users or rates: {str(e)}")
        flash('Error fetching user list or rates.')
        users = []
        mb_per_credit, usd_per_credit = 1.0, 0.01  # Fallback defaults

    return render_template('admin.html', users=users, search_query='',
                           mb_per_credit=mb_per_credit, usd_per_credit=usd_per_credit)

# Initialize database on app startup
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
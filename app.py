from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime, timedelta
import json
from functools import wraps
import secrets
from datetime import datetime, timedelta
from flask import render_template

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Socket.IO
socketio = SocketIO(app, cors_allowed_origins="*")

# Database setup
DATABASE = 'turfease.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        division TEXT,
        is_admin BOOLEAN DEFAULT 0,
        is_active BOOLEAN DEFAULT 0,
        password_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

    
    # Bookings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            turf_side TEXT NOT NULL,
            booking_date DATE NOT NULL,
            time_slot TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Chat messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Notices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create default admin user
    admin_email = 'admin@ves.ac.in'
    admin_name = 'Sports Council Admin'
    admin_division = 'Admin'
    admin_password = 'adminpassword'  # Change to strong password or environment variable
    admin_pw_hash = generate_password_hash(admin_password)

    cursor.execute('''
        INSERT OR IGNORE INTO users (email, name, division, is_admin, is_active, password_hash)
        VALUES (?, ?, ?, 1, 1, ?)
    ''', (admin_email, admin_name, admin_division, admin_pw_hash))
    
    conn.commit()
    conn.close()



class User(UserMixin):
    def __init__(self, id, email, name, division, is_admin, is_active_flag):
        self.id = id
        self.email = email
        self.name = name
        self.division = division
        self.is_admin = is_admin
        self._is_active_flag = is_active_flag  # Custom variable

    @property
    def is_active(self):
        return bool(self._is_active_flag)  # Overriding default property safely


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(
            user_data[0],  # id
            user_data[1],  # email
            user_data[2],  # name
            user_data[3],  # division
            user_data[4],  # is_admin
            user_data[5],  # is_active (adjust index if needed)
        )
    return None
# inside load_user

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Time slots configuration
TIME_SLOTS = [
    '06:00-07:00', '07:00-08:00', '08:00-09:00', '09:00-10:00',
    '10:00-11:00', '11:00-12:00', '12:00-13:00', '13:00-14:00',
    '14:00-15:00', '15:00-16:00', '16:00-17:00', '17:00-18:00',
    '18:00-19:00', '19:00-20:00', '20:00-21:00', '21:00-22:00'
]

TURF_SIDES = ['Football', 'Cricket']

@app.route('/')
@login_required
def index():
    conn = get_db_connection()

    # Get all bookings for display
    all_bookings = conn.execute('''
        SELECT b.*, u.name, u.email, u.division
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE b.status = 'approved'
        ORDER BY b.booking_date ASC, time_slot ASC
    ''').fetchall()

    conn.close()

    return render_template('dashboard.html',
                           bookings=all_bookings,
                           is_admin=current_user.is_admin,
                           user=current_user)


from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        division = request.form.get('division', 'General')
        password = request.form.get('password')
        is_admin = True if request.form.get('is_admin') == 'on' else False
        
        # Basic validation
        if not email.endswith('@ves.ac.in'):
            flash('Please use your college email (@ves.ac.in)', 'error')
            return render_template('register.html')

        conn = get_db_connection()
        existing = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if existing:
            flash('Email already registered.', 'error')
            conn.close()
            return render_template('register.html')

        pw_hash = generate_password_hash(password)

        is_active = 0 if is_admin else 1  # Admin registrations need approval

        conn.execute('''
            INSERT INTO users (email, name, division, is_admin, is_active, password_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (email, name, division, is_admin, is_active, pw_hash))
        conn.commit()
        conn.close()

        if is_admin:
            flash('Admin registration submitted. Await approval by main admin.', 'info')
        else:
            flash('User registration successful! You can login now.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if not user:
            flash('User not found.', 'error')
            return render_template('login.html')

        if not check_password_hash(user['password_hash'], password):
            flash('Incorrect password.', 'error')
            return render_template('login.html')

        if user['is_admin'] and not user['is_active']:
            flash('Admin registration not approved yet.', 'error')
            return render_template('login.html')

        # inside /login route
        user_obj = User(
            user['id'],
            user['email'],
            user['name'],
            user['division'],
            user['is_admin'],
            user['is_active']
        )


        login_user(user_obj, remember=True)
        flash('Login successful!', 'success')
        return redirect(url_for('index'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

from datetime import datetime, timedelta

@app.route('/dashboard')
@login_required
def dashboard():
    today = datetime.today().date()
    start_of_week = today - timedelta(days=today.weekday())  # Monday
    end_of_week = start_of_week + timedelta(days=6)          # Sunday

    conn = get_db_connection()

    # Current user's bookings
    user_bookings = conn.execute('''
        SELECT * FROM bookings
        WHERE user_id = ?
        ORDER BY booking_date DESC, time_slot ASC
    ''', (current_user.id,)).fetchall()

    # Notices (latest 5)
    notices = conn.execute('''
        SELECT * FROM notices
        ORDER BY created_at DESC
        LIMIT 5
    ''').fetchall()

    # Weekly bookings (all users, between start_of_week and end_of_week)
    weekly_bookings = conn.execute('''
        SELECT b.*, u.name, u.email, u.division
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE booking_date BETWEEN ? AND ?
        ORDER BY booking_date, time_slot
    ''', (start_of_week, end_of_week)).fetchall()

    conn.close()

    return render_template('dashboard.html',
        user=current_user,
        bookings=user_bookings,
        notices=notices,
        weekly_bookings=weekly_bookings
    )



@app.route('/book', methods=['GET', 'POST'])
@login_required
def book_turf():
    if request.method == 'POST':
        turf_side = request.form.get('turf_side')
        booking_date = request.form.get('booking_date')
        time_slot = request.form.get('time_slot')
        
        # Validate booking date (max 7 days ahead)
        try:
            booking_date_obj = datetime.strptime(booking_date, '%Y-%m-%d').date()
            today = datetime.now().date()
            max_date = today + timedelta(days=7)
            
            if booking_date_obj < today:
                flash('Cannot book for past dates.', 'error')
                return redirect(url_for('book_turf'))
            
            if booking_date_obj > max_date:
                flash('Cannot book more than 7 days in advance.', 'error')
                return redirect(url_for('book_turf'))
        except ValueError:
            flash('Invalid date format.', 'error')
            return redirect(url_for('book_turf'))
        
        conn = get_db_connection()
        
        # Check if user already has a booking for this date
        existing_booking = conn.execute('''
            SELECT * FROM bookings 
            WHERE user_id = ? AND booking_date = ? AND status != 'declined'
        ''', (current_user.id, booking_date)).fetchone()
        
        if existing_booking:
            flash('You already have a booking for this date.', 'error')
            conn.close()
            return redirect(url_for('book_turf'))
        
        # Check if slot is available
        slot_taken = conn.execute('''
            SELECT * FROM bookings 
            WHERE turf_side = ? AND booking_date = ? AND time_slot = ? AND status = 'approved'
        ''', (turf_side, booking_date, time_slot)).fetchone()
        
        if slot_taken:
            flash('This slot is already booked.', 'error')
            conn.close()
            return redirect(url_for('book_turf'))
        
        # Create booking
        conn.execute('''
            INSERT INTO bookings (user_id, turf_side, booking_date, time_slot)
            VALUES (?, ?, ?, ?)
        ''', (current_user.id, turf_side, booking_date, time_slot))
        conn.commit()
        conn.close()
        
        flash('Booking request submitted successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template("booking.html", 
                                time_slots=TIME_SLOTS, 
                                turf_sides=TURF_SIDES,
                                datetime=datetime,
                                timedelta=timedelta)

@app.route('/api/check_availability')
@login_required
def check_availability():
    turf_side = request.args.get('turf_side')
    booking_date = request.args.get('booking_date')
    
    conn = get_db_connection()
    booked_slots = conn.execute('''
        SELECT time_slot FROM bookings 
        WHERE turf_side = ? AND booking_date = ? AND status = 'approved'
    ''', (turf_side, booking_date)).fetchall()
    conn.close()
    
    booked_times = [slot['time_slot'] for slot in booked_slots]
    available_slots = [slot for slot in TIME_SLOTS if slot not in booked_times]
    
    return jsonify(available_slots)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = request.form.get('name')
        division = request.form.get('division')
        
        conn = get_db_connection()
        conn.execute('''
            UPDATE users SET name = ?, division = ? WHERE id = ?
        ''', (name, division, current_user.id))
        conn.commit()
        conn.close()
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    conn = get_db_connection()
    bookings = conn.execute('''
        SELECT * FROM bookings 
        WHERE user_id = ? 
        ORDER BY booking_date DESC, created_at DESC
    ''', (current_user.id,)).fetchall()
    conn.close()
    
    return render_template("profile.html", 
                                user=current_user, 
                                bookings=bookings)


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    
    # Get all pending bookings
    pending_bookings = conn.execute('''
        SELECT b.*, u.name, u.email, u.division 
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE b.status = 'pending'
        ORDER BY b.booking_date ASC, b.created_at ASC
    ''').fetchall()
    
    # Get statistics
    total_bookings = conn.execute('SELECT COUNT(*) as count FROM bookings').fetchone()['count']
    approved_bookings = conn.execute('SELECT COUNT(*) as count FROM bookings WHERE status = "approved"').fetchone()['count']
    pending_count = conn.execute('SELECT COUNT(*) as count FROM bookings WHERE status = "pending"').fetchone()['count']
    
    conn.close()
    
    return render_template("admin_dashboard.html",
                                pending_bookings=pending_bookings,
                                total_bookings=total_bookings,
                                approved_bookings=approved_bookings,
                                pending_count=pending_count)

@app.route('/admin/booking/<int:booking_id>/<action>')
@admin_required
def admin_booking_action(booking_id, action):
    reason = request.args.get('reason', '')
    
    if action not in ['approve', 'decline']:
        flash('Invalid action.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    status = 'approved' if action == 'approve' else 'declined'
    
    conn = get_db_connection()
    conn.execute('''
        UPDATE bookings 
        SET status = ?, reason = ? 
        WHERE id = ?
    ''', (status, reason, booking_id))
    conn.commit()
    conn.close()
    
    flash(f'Booking {status} successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/approve_admin/<int:user_id>')
@admin_required
def approve_admin(user_id):
    # Only main admin can approve
    if current_user.email != 'admin@ves.ac.in':
        flash('Only main admin can approve admins.', 'error')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    conn.execute('UPDATE users SET is_active = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('Admin approved successfully.', 'success')
    return redirect(url_for('admin_pending_approvals'))

@app.route('/admin/pending_admins')
@admin_required
def admin_pending_approvals():
    if current_user.email != 'admin@ves.ac.in':
        flash('Only main admin can view this page.', 'error')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    pending_admins = conn.execute('SELECT * FROM users WHERE is_admin = 1 AND is_active = 0').fetchall()
    conn.close()

    return render_template('admin_pending_approvals.html', pending_admins=pending_admins)





@app.route('/admin/notices', methods=['GET', 'POST'])
@admin_required
def admin_notices():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO notices (title, content)
            VALUES (?, ?)
        ''', (title, content))
        conn.commit()
        conn.close()
        
        flash('Notice posted successfully!', 'success')
        return redirect(url_for('admin_notices'))
    
    conn = get_db_connection()
    notices = conn.execute('''
        SELECT * FROM notices 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template("admin_notices.html", notices=notices)

@app.route('/chat')
@login_required
def chat():
    conn = get_db_connection()
    messages = conn.execute('''
        SELECT cm.*, u.name 
        FROM chat_messages cm
        JOIN users u ON cm.user_id = u.id
        ORDER BY cm.created_at ASC
    ''').fetchall()
    conn.close()
    
    return render_template("chat.html", messages=messages)

# Socket.IO events
@socketio.on('join')
def on_join(data):
    room = 'chat_room'
    join_room(room)
    emit('status', {'msg': f'{current_user.name} has entered the chat.'}, room=room)

@socketio.on('leave')
def on_leave(data):
    room = 'chat_room'
    leave_room(room)
    emit('status', {'msg': f'{current_user.name} has left the chat.'}, room=room)

@socketio.on('message')
def handle_message(data):
    room = 'chat_room'
    message = data['message']
    
    # Save message to database
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO chat_messages (user_id, message, is_admin)
        VALUES (?, ?, ?)
    ''', (current_user.id, message, current_user.is_admin))
    conn.commit()
    conn.close()
    
    emit('message', {
        'message': message,
        'name': current_user.name,
        'is_admin': current_user.is_admin,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }, room=room)

# PWA Routes
@app.route('/manifest.json')
def manifest():
    return jsonify({
        "name": "TurfEase",
        "short_name": "TurfEase",
        "description": "College Turf Booking System",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#4f46e5",
        "icons": [
            {
                "src": "/static/icon-192x192.png",
                "sizes": "192x192",
                "type": "image/png"
            },
            {
                "src": "/static/icon-512x512.png",
                "sizes": "512x512",
                "type": "image/png"
            }
        ]
    })

@app.route('/sw.js')
def service_worker():
    return '''
const CACHE_NAME = 'turfease-v1';
const urlsToCache = [
    '/',
    '/static/style.css',
    '/static/script.js'
];

self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                return cache.addAll(urlsToCache);
            })
    );
});

self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request)
            .then(function(response) {
                if (response) {
                    return response;
                }
                return fetch(event.request);
            })
    );
});
''', 200, {'Content-Type': 'application/javascript'}

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)

     
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
    
    # Turf availability table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS turf_availability (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            turf_side TEXT NOT NULL,
            day_of_week TEXT NOT NULL,  -- e.g., 'Monday'
            start_time TEXT NOT NULL,   -- e.g., '04:00'
            end_time TEXT NOT NULL      -- e.g., '22:00'
        )
    ''')
    
    # Events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            event_link TEXT,
            deadline DATE NOT NULL,
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
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    conn = get_db_connection()
    user_bookings = conn.execute('''
        SELECT b.*, u.name, u.email, u.division
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE b.user_id = ?
        ORDER BY b.booking_date DESC, time_slot ASC
    ''', (current_user.id,)).fetchall()
    notices = conn.execute('''
        SELECT * FROM notices
        ORDER BY created_at DESC
        LIMIT 5
    ''').fetchall()
    today = datetime.today().date()
    start_of_week = today - timedelta(days=today.weekday())
    end_of_week = start_of_week + timedelta(days=6)
    weekly_bookings = conn.execute('''
        SELECT b.*, u.name, u.email, u.division
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE booking_date BETWEEN ? AND ?
        ORDER BY booking_date, time_slot
    ''', (start_of_week, end_of_week)).fetchall()
    conn.close()
    return render_template('dashboard.html',
                           bookings=user_bookings,
                           is_admin=False,
                           user=current_user,
                           notices=notices,
                           weekly_bookings=weekly_bookings)


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

def cleanup_notices_and_events():
    conn = get_db_connection()
    # Delete notices older than 3 days
    three_days_ago = (datetime.now() - timedelta(days=3)).strftime('%Y-%m-%d %H:%M:%S')
    conn.execute("DELETE FROM notices WHERE created_at < ?", (three_days_ago,))
    # Delete events past their deadline
    today = datetime.now().strftime('%Y-%m-%d')
    conn.execute("DELETE FROM events WHERE deadline < ?", (today,))
    conn.commit()
    conn.close()

# Call this at the start of each dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    cleanup_notices_and_events()
    # Redirect admins to the admin dashboard
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

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

    # Events (only those with deadline >= today)
    events = conn.execute('''
        SELECT * FROM events
        WHERE deadline >= ?
        ORDER BY deadline ASC
    ''', (today.strftime('%Y-%m-%d'),)).fetchall()

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
        events=events,  # <-- Pass events to template
        weekly_bookings=weekly_bookings
    )



@app.route('/book', methods=['GET', 'POST'])
@login_required
def book_turf():
    if request.method == 'POST':
        turf_side = request.form.get('turf_side')
        booking_date = request.form.get('booking_date')
        time_slot = request.form.get('time_slot')
        
        try:
            conn = get_db_connection()

            # Only restrict normal users to one booking per day
            if not current_user.is_admin:
                existing_booking = conn.execute('''
                    SELECT * FROM bookings 
                    WHERE user_id = ? AND booking_date = ? AND status != 'declined'
                ''', (current_user.id, booking_date)).fetchone()
                
                if existing_booking:
                    flash('You already have a booking for this date.', 'error')
                    conn.close()
                    return redirect(url_for('book_turf'))
            # Admins can book multiple slots per day

            # Check if slot is available (for all users)
            slot_taken = conn.execute('''
                SELECT * FROM bookings 
                WHERE turf_side = ? AND booking_date = ? AND time_slot = ? AND status = 'approved'
            ''', (turf_side, booking_date, time_slot)).fetchone()
            
            if slot_taken:
                flash('This slot is already booked.', 'error')
                conn.close()
                return redirect(url_for('book_turf'))
            
            # Check if slot is within allowed availability
            booking_date_obj = datetime.strptime(booking_date, '%Y-%m-%d').date()
            day_of_week = booking_date_obj.strftime('%A')
            slot_start = time_slot.split('-')[0]
            slot_end = time_slot.split('-')[1]
            availability = conn.execute('''
                SELECT * FROM turf_availability
                WHERE turf_side = ? AND day_of_week = ?
                  AND start_time <= ? AND end_time >= ?
            ''', (turf_side, day_of_week, slot_start, slot_end)).fetchone()
            if not availability:
                flash('This slot is not available for booking as per turf timings.', 'error')
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
        except Exception as e:
            flash('An error occurred while booking. Please try again.', 'error')
            return redirect(url_for('book_turf'))
    
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

    # Get day of week
    import datetime
    day_of_week = datetime.datetime.strptime(booking_date, '%Y-%m-%d').strftime('%A')

    conn = get_db_connection()
    # Get allowed time ranges for this turf and day
    allowed_ranges = conn.execute('''
        SELECT start_time, end_time FROM turf_availability
        WHERE turf_side = ? AND day_of_week = ?
    ''', (turf_side, day_of_week)).fetchall()

    # Get already booked slots
    booked_slots = conn.execute('''
        SELECT time_slot FROM bookings 
        WHERE turf_side = ? AND booking_date = ? AND status = 'approved'
    ''', (turf_side, booking_date)).fetchall()
    conn.close()

    booked_times = [slot['time_slot'] for slot in booked_slots]

    # Filter TIME_SLOTS: must be within allowed_ranges and not booked
    def is_within_ranges(slot):
        slot_start, slot_end = slot.split('-')
        for rng in allowed_ranges:
            if rng['start_time'] <= slot_start and rng['end_time'] >= slot_end:
                return True
        return False

    available_slots = [
        slot for slot in TIME_SLOTS
        if is_within_ranges(slot) and slot not in booked_times
    ]

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
    cleanup_notices_and_events()
    # Handle direct week selection by date
    week_start_str = request.args.get('week_start')
    if week_start_str:
        start_of_week = datetime.strptime(week_start_str, '%Y-%m-%d').date()
        start_of_week = start_of_week - timedelta(days=start_of_week.weekday())
        week_offset = ((start_of_week - datetime.today().date()).days) // 7
    else:
        week_offset = int(request.args.get('week', 0))
        today = datetime.today().date()
        start_of_week = today - timedelta(days=today.weekday()) + timedelta(weeks=week_offset)
    end_of_week = start_of_week + timedelta(days=6)

    conn = get_db_connection()

    # Get all bookings for the selected week with user info
    week_bookings = conn.execute('''
        SELECT b.*, u.name, u.email, u.division
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE b.booking_date BETWEEN ? AND ?
        ORDER BY b.booking_date, b.time_slot
    ''', (start_of_week, end_of_week)).fetchall()

    # Notices (latest 5)
    notices = conn.execute('''
        SELECT * FROM notices
        ORDER BY created_at DESC
        LIMIT 5
    ''').fetchall()

    # Statistics for dashboard cards
    total_bookings = conn.execute('SELECT COUNT(*) FROM bookings').fetchone()[0]
    approved_bookings = conn.execute("SELECT COUNT(*) FROM bookings WHERE status = 'approved'").fetchone()[0]
    pending_count = conn.execute("SELECT COUNT(*) FROM bookings WHERE status = 'pending'").fetchone()[0]
    pending_bookings = conn.execute('''
        SELECT b.*, u.name, u.email, u.division
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE b.status = 'pending'
        ORDER BY b.booking_date, b.time_slot
    ''').fetchall()

    # --- Fetch admin's own bookings for "Your Recent Bookings" ---
    my_bookings = conn.execute('''
        SELECT b.*, u.name, u.email, u.division
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE b.user_id = ?
        ORDER BY b.booking_date DESC, time_slot ASC
    ''', (current_user.id,)).fetchall()

    conn.close()

    # Prepare bookings in a dict: {date: {turf_side: [bookings...]}}
    calendar = {}
    for i in range(7):
        day = (start_of_week + timedelta(days=i)).strftime('%Y-%m-%d')
        calendar[day] = {turf: [] for turf in TURF_SIDES}

    for booking in week_bookings:
        day = booking['booking_date']
        turf = booking['turf_side']
        calendar[day][turf].append(booking)

    return render_template(
        "admin_dashboard.html",
        calendar=calendar,
        start_of_week=start_of_week,
        end_of_week=end_of_week,
        week_offset=week_offset,
        TURF_SIDES=TURF_SIDES,
        notices=notices,
        total_bookings=total_bookings,
        approved_bookings=approved_bookings,
        pending_count=pending_count,
        pending_bookings=pending_bookings,
        bookings=my_bookings,  # <-- Pass admin's own bookings here
        is_admin=True,
        user=current_user,
        weekly_bookings=week_bookings
    )


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
        event_link = request.form.get('event_link')  # New: optional event/form/instagram link

        # Combine content and link for display (or store as separate columns if you wish)
        if event_link:
            # You can style this in your template as needed
            content = f"{content}<br><a href='{event_link}' target='_blank'>{event_link}</a>"

        conn = get_db_connection()
        conn.execute('''
            INSERT INTO notices (title, content)
            VALUES (?, ?)
        ''', (title, content))
        conn.commit()
        conn.close()
        
        flash('Notice/event posted successfully!', 'success')
        return redirect(url_for('admin_notices'))
    
    conn = get_db_connection()
    notices = conn.execute('''
        SELECT * FROM notices 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    
    from datetime import datetime

    today_str = datetime.now().strftime('%Y-%m-%d')
    notices_today = [n for n in notices if n['created_at'].startswith(today_str)]
    notices_today_count = len(notices_today)

    return render_template("admin_notices.html", notices=notices, notices_today_count=notices_today_count)

@app.route('/admin/turf_availability', methods=['GET', 'POST'])
@admin_required
def turf_availability():
    conn = get_db_connection()
    if request.method == 'POST':
        turf_side = request.form.get('turf_side')
        day_of_week = request.form.get('day_of_week')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        conn.execute('''
            INSERT INTO turf_availability (turf_side, day_of_week, start_time, end_time)
            VALUES (?, ?, ?, ?)
        ''', (turf_side, day_of_week, start_time, end_time))
        conn.commit()
        flash('Turf availability updated.', 'success')
    availabilities = conn.execute('SELECT * FROM turf_availability').fetchall()
    conn.close()
    return render_template('admin_turf_availability.html', availabilities=availabilities, turf_sides=TURF_SIDES)

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

@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    conn = get_db_connection()
    # Only allow user to cancel their own booking and only if not already declined/cancelled
    booking = conn.execute(
        'SELECT * FROM bookings WHERE id = ? AND user_id = ?', (booking_id, current_user.id)
    ).fetchone()
    if not booking:
        conn.close()
        flash('Booking not found or not authorized.', 'error')
        return redirect(url_for('dashboard'))

    if booking['status'] in ['declined', 'cancelled']:
        conn.close()
        flash('Booking already declined or cancelled.', 'info')
        return redirect(url_for('dashboard'))

    conn.execute(
        'UPDATE bookings SET status = ? WHERE id = ?', ('cancelled', booking_id)
    )
    conn.commit()
    conn.close()
    flash('Booking cancelled successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/availability/<int:availability_id>/delete', methods=['DELETE'])
@admin_required
def delete_availability(availability_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM turf_availability WHERE id = ?', (availability_id,))
    conn.commit()
    conn.close()
    return '', 204  # No Content, signals success for fetch API

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%A, %d %b'):
    return datetime.strptime(value, '%Y-%m-%d').strftime(format)

@app.route('/admin/add_event', methods=['POST'])
@admin_required
def admin_add_event():
    title = request.form['title']
    content = request.form['content']
    event_link = request.form.get('event_link')
    deadline = request.form['deadline']
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO events (title, content, event_link, deadline)
        VALUES (?, ?, ?, ?)
    ''', (title, content, event_link, deadline))
    conn.commit()
    conn.close()
    flash('Event added!', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)


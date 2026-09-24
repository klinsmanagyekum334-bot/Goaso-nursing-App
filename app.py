import os
import uuid
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, redirect, url_for, flash,
                   request, session, jsonify, send_from_directory)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dateutil.relativedelta import relativedelta
from dotenv import load_dotenv
from sqlalchemy import func as safunc

# ---------- Load .env from the same folder as this file ----------
# Bulletproof on Pydroid / any host, regardless of the current working directory.
BASEDIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASEDIR, '.env'))

from models import (db, User, Event, News, ContactMessage, Contribution,
                    Payment, SiteSetting, HomeCard, AboutPerson,
                    GuestAdmin, GalleryImage, Announcement,
                    Poll, PollOption, PollVote, Student,
                    SRCExecutive, PastLeader, PollRequest,
                    YearGroup, SignupRequest, RecoveryRequest, Complaint)


# ============================================================
# SUPABASE CLIENT (for file storage)
# ============================================================
try:
    from supabase import create_client, Client
    SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '') or os.environ.get('SUPABASE_ANON_KEY', '')
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY) if (SUPABASE_URL and SUPABASE_KEY) else None
except ImportError:
    supabase = None


# ============================================================
# APP CONFIG
# ============================================================
app = Flask(__name__)

# ---------- SECRET KEY ----------
_secret = os.environ.get('SECRET_KEY')
if not _secret:
    if os.environ.get('FLASK_ENV') == 'production':
        raise RuntimeError("SECRET_KEY must be set in production.")
    _secret = 'dev-only-insecure-key-change-me'
app.config['SECRET_KEY'] = _secret

# ---------- CSRF ----------
csrf = CSRFProtect(app)

# ---------- DATABASE ----------
db_url = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(BASEDIR, 'alumni.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if db_url.startswith('postgresql'):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 5,
        'max_overflow': 10,
        'connect_args': {'sslmode': 'require'},
    }

# ---------- UPLOAD FOLDER ----------
app.config['UPLOAD_FOLDER'] = os.path.join(BASEDIR, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024

# ---------- SESSIONS ----------
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_DOC_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'ppt', 'pptx', 'xls', 'xlsx'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# ---------- LOGGING ----------
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_doc(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_DOC_EXTENSIONS


# ============================================================
# CSRF ERROR HANDLER
# ============================================================
@app.errorhandler(CSRFError)
def handle_csrf(e):
    flash('Your session expired or the form was tampered with. Please try again.', 'danger')
    return redirect(request.referrer or url_for('index'))


# ============================================================
# AUTH DECORATORS
# ============================================================
def student_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Admins hitting a student page are sent back to their panel
        if session.get('super_admin_logged_in'):
            return redirect(url_for('super_admin'))
        if not session.get('student_logged_in'):
            flash('Please log in to continue.', 'info')
            return redirect(url_for('member_login'))
        if not Student.query.get(session.get('student_db_id')):
            session.pop('student_logged_in', None)
            session.pop('student_db_id', None)
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('member_login'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('super_admin_logged_in'):
            flash('Super Admin access only.', 'info')
            return redirect(url_for('member_login'))
        return f(*args, **kwargs)
    return wrapper


# ============================================================
# TEMPLATE HELPERS
# ============================================================
def img_url(val):
    """Return a usable URL for a stored image value (Supabase URL or local filename)."""
    if not val:
        return ''
    if isinstance(val, str) and (val.startswith('http://') or val.startswith('https://')):
        return val
    return url_for('static', filename=f'uploads/{val}')


def is_remote(val):
    return isinstance(val, str) and (val.startswith('http://') or val.startswith('https://'))


def _int(key, default=0):
    """Safely parse an integer form field."""
    try:
        return int(request.form.get(key, default) or default)
    except (TypeError, ValueError):
        return default


app.jinja_env.globals['img_url'] = img_url


# ============================================================
# FILE UPLOAD — Supabase Storage with local fallback
# ============================================================
def save_upload(file):
    """Returns a public URL (Supabase) OR a local filename. Use img_url() to render."""
    if not (file and file.filename and allowed_file(file.filename)):
        return None

    ext = file.filename.rsplit('.', 1)[1].lower()
    fn = f"{uuid.uuid4().hex[:10]}.{ext}"

    if supabase:
        try:
            file_bytes = file.read()
            supabase.storage.from_('uploads').upload(
                path=fn,
                file=file_bytes,
                file_options={"content-type": file.content_type or "image/jpeg"}
            )
            return supabase.storage.from_('uploads').get_public_url(fn)
        except Exception as e:
            app.logger.error(f"[Supabase upload failed] {e}")

    file.seek(0)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], fn))
    return fn


def save_doc(file):
    if not (file and file.filename and allowed_doc(file.filename)):
        return None, None

    ext = file.filename.rsplit('.', 1)[1].lower()
    fn = f"{uuid.uuid4().hex[:10]}.{ext}"
    original_name = secure_filename(file.filename)

    if supabase:
        try:
            file_bytes = file.read()
            supabase.storage.from_('uploads').upload(
                path=fn,
                file=file_bytes,
                file_options={"content-type": file.content_type or "application/octet-stream"}
            )
            public_url = supabase.storage.from_('uploads').get_public_url(fn)
            return public_url, original_name
        except Exception as e:
            app.logger.error(f"[Supabase doc upload failed] {e}")

    file.seek(0)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], fn))
    return fn, original_name


# ============================================================
# HELPERS
# ============================================================
def build_poll_data(poll, voter_id=None):
    rows = (db.session.query(PollVote.option_id, safunc.count(PollVote.id))
              .filter(PollVote.poll_id == poll.id)
              .group_by(PollVote.option_id).all())
    counts = {oid: c for oid, c in rows}
    total = sum(counts.values())

    options_data = []
    for opt in poll.options:
        count = counts.get(opt.id, 0)
        pct = round((count / total * 100), 1) if total > 0 else 0
        options_data.append({
            'id': opt.id, 'name': opt.name, 'image': opt.image,
            'count': count, 'percent': pct,
        })

    user_vote = None
    if voter_id:
        v = PollVote.query.filter_by(poll_id=poll.id, voter_id=voter_id).first()
        if v:
            user_vote = v.option_id

    return {
        'id': poll.id, 'question': poll.question, 'description': poll.description,
        'total_votes': total, 'options': options_data, 'user_vote': user_vote,
    }


def get_year_group_options():
    current = datetime.utcnow().year
    return [str(y) for y in range(2009, current + 4)]


def get_dob_years():
    current = datetime.utcnow().year
    return [str(y) for y in range(current, 1959, -1)]


def get_guest_settings():
    return {
        'president_name': SiteSetting.get('guest_president_name', 'Ms. Akosua Mensah'),
        'president_title': SiteSetting.get('guest_president_title', 'SRC President 2025/2026'),
        'president_photo': SiteSetting.get('guest_president_photo', 'https://i.pravatar.cc/240?img=47'),
        'principal_name': SiteSetting.get('guest_principal_name', 'Mrs. Yaa Boateng'),
        'principal_title': SiteSetting.get('guest_principal_title', 'Principal, GNMTC'),
        'principal_photo': SiteSetting.get('guest_principal_photo', 'https://i.pravatar.cc/240?img=32'),
        'aim': SiteSetting.get('guest_aim',
            "To train compassionate, competent, and ethically grounded midwives."),
        'ambition': SiteSetting.get('guest_ambition',
            "To become the leading midwifery training institution in Ghana."),
        'courses': [c.strip() for c in SiteSetting.get('guest_courses',
            "Registered General Nursing (RGN)\nRegistered Midwifery (RM)\nPost-Basic Midwifery\n"
            "Community Health Nursing\nCritical Care Nursing (in partnership)").split('\n') if c.strip()],
        'location': SiteSetting.get('guest_location', 'Goaso, Ahafo Region, Ghana'),
        'email': SiteSetting.get('guest_email', 'info@gnmtc.edu.gh'),
        'website': SiteSetting.get('guest_website', 'www.gnmtc.edu.gh'),
        'phone': SiteSetting.get('guest_phone', '+233 24 000 0000'),
        'whatsapp': SiteSetting.get('guest_whatsapp', '233240000000'),
        'about': SiteSetting.get('guest_about',
            "Goaso Midwifery and Training College (GNMTC) is a premier health training institution."),
        'gallery_heading': SiteSetting.get('guest_gallery_heading', 'Gallery'),
    }


# ============================================================
# CREDENTIALS
# ============================================================
SUPER_ADMIN_ID = os.environ.get('SUPER_ADMIN_ID', '1234')
SUPER_ADMIN_PASSWORD = os.environ.get('SUPER_ADMIN_PASSWORD')
if not SUPER_ADMIN_PASSWORD:
    if os.environ.get('FLASK_ENV') == 'production':
        raise RuntimeError("SUPER_ADMIN_PASSWORD must be set in production.")
    SUPER_ADMIN_PASSWORD = '1234'  # dev only

RESERVED_IDS = {SUPER_ADMIN_ID.lower(), 'admin', 'root', 'superadmin'}


# ============================================================
# CONTEXT PROCESSORS
# ============================================================
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


@app.context_processor
def inject_session_flags():
    return {
        'student_logged_in': session.get('student_logged_in', False),
        'super_admin_logged_in': session.get('super_admin_logged_in', False),
    }


@app.context_processor
def inject_footer_about():
    default = ("Goaso Midwifery and Training College — training compassionate, "
               "competent midwives for Ghana and beyond since December 2010.")
    try:
        val = SiteSetting.get('footer_about', default)
    except Exception as e:
        app.logger.warning(f"footer_about lookup failed: {e}")
        val = default
    return {'footer_about': val}


# ============================================================
# DEFAULT CONTENT
# ============================================================
DEFAULT_ABOUT_HISTORY = """The school began as a post basic midwifery training school in December 2010 under the auspices of the then Municipal Chief Executive — Hon. Mohammed Kwaku Doku — and the Late Omanhene of Goaso Traditional Area — Nana Kwasi Baffour Bosompra — who both saw the need to train midwives to augment the staff strength of health facilities in Asunafo North Municipality and, by extension, to other parts of the country.

The school commenced with 42 students who were serving officers as enrolled nurses and community health nurses in the Ghana Health Service, drawn from various parts of the country. It began on a single campus that served as a hostel, administration and lecture hall — on the kind donation by Presby Church of Ghana, Trinity Congregation, Goaso — before it finally moved to its present location.

The school has been managed under two former principals in the persons of Hajia Halima Opoku Ahmed and Mr. Samuel Ansu Frimpong.

Close to 16 years of its inception, the school has produced over 5,000 midwives and nurses. Starting with a staff strength of 8 and 42 students, the college now boasts of about 900 students with a staff strength of over 50 — including teaching and non-teaching staff."""


# ============================================================
# HEALTH CHECK
# ============================================================
@app.route('/healthz')
def healthz():
    return 'ok', 200


# ============================================================
# SPLASH SCREEN
# ============================================================
@app.route('/splash')
def splash():
    return render_template('splash.html')


# ============================================================
# PWA MANIFEST
# ============================================================
@app.route('/manifest.json')
def manifest():
    return {
        "name": "GNMTC SRC APP",
        "short_name": "GNMTC SRC",
        "description": "Goaso Midwifery & Training College — SRC App",
        "start_url": "/splash",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait",
        "background_color": "#1a6b47",
        "theme_color": "#1a6b47",
        "icons": [
            {
                "src": url_for('static', filename='uploads/logo.png', _external=True),
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "any maskable"
            },
            {
                "src": url_for('static', filename='uploads/logo.png', _external=True),
                "sizes": "512x512",
                "type": "image/png",
                "purpose": "any maskable"
            }
        ]
    }


@app.route('/apple-touch-icon.png')
@app.route('/apple-touch-icon-precomposed.png')
def apple_touch_icon():
    return redirect(url_for('static', filename='uploads/logo.png'))


# ============================================================
# HOME
# ============================================================
@app.route('/')
def index():
    home_title = SiteSetting.get('home_title', 'This is the SRC App for GNMTC')
    home_subtitle = SiteSetting.get('home_subtitle',
        "Goaso Midwifery & Training College — Students' Representative Council")
    home_cards = HomeCard.query.order_by(HomeCard.order.asc()).all()
    upcoming_events = Event.query.filter(Event.event_date >= datetime.utcnow()) \
        .order_by(Event.event_date.asc()).limit(3).all()
    latest_news = News.query.order_by(News.posted_at.desc()).limit(3).all()
    stats = {
        'members': Student.query.count(),
        'events': Event.query.count(),
        'news': News.query.count(),
    }
    return render_template('index.html',
                           home_title=home_title, home_subtitle=home_subtitle,
                           home_cards=home_cards, events=upcoming_events,
                           news=latest_news, stats=stats)


# ============================================================
# ABOUT
# ============================================================
@app.route('/about')
def about():
    about_title = SiteSetting.get('about_title', 'Goaso Midwifery & Training College')
    about_tagline = SiteSetting.get('about_tagline',
        'A story of vision, service, and the training of thousands of midwives for Ghana and beyond.')
    about_history = SiteSetting.get('about_history', DEFAULT_ABOUT_HISTORY)
    about_stats = [
        {'value': SiteSetting.get('about_stat_1_value', '2010'),
         'label': SiteSetting.get('about_stat_1_label', 'Established')},
        {'value': SiteSetting.get('about_stat_2_value', '5,000+'),
         'label': SiteSetting.get('about_stat_2_label', 'Midwives & Nurses Trained')},
        {'value': SiteSetting.get('about_stat_3_value', '~900'),
         'label': SiteSetting.get('about_stat_3_label', 'Current Students')},
        {'value': SiteSetting.get('about_stat_4_value', '50+'),
         'label': SiteSetting.get('about_stat_4_label', 'Staff Members')},
    ]
    about_people = AboutPerson.query.order_by(AboutPerson.order.asc()).all()
    paragraphs = [p.strip() for p in about_history.split('\n\n') if p.strip()]
    return render_template('about.html',
                           about_title=about_title, about_tagline=about_tagline,
                           about_paragraphs=paragraphs, about_history=about_history,
                           about_stats=about_stats, about_people=about_people)


# ============================================================
# GUEST
# ============================================================
@app.route('/guest')
def guest():
    info = get_guest_settings()
    administration = GuestAdmin.query.order_by(GuestAdmin.order.asc()).all()
    gallery = GalleryImage.query.order_by(GalleryImage.order.asc()).all()
    return render_template('guest.html', info=info,
                           administration=administration, gallery=gallery)


# ============================================================
# PUBLIC MISC
# ============================================================
@app.route('/directory')
@login_required
def directory():
    search = request.args.get('q', '').strip()
    query = User.query
    if search:
        query = query.filter(
            (User.full_name.ilike(f'%{search}%')) |
            (User.program.ilike(f'%{search}%')) |
            (User.graduation_year.ilike(f'%{search}%'))
        )
    members = query.order_by(User.full_name.asc()).all()
    return render_template('directory.html', members=members, search=search)


@app.route('/events')
def events():
    return render_template('events.html',
                           events=Event.query.order_by(Event.event_date.desc()).all())


@app.route('/news')
def news():
    return render_template('news.html',
                           news=News.query.order_by(News.posted_at.desc()).all())


@app.route('/news/<int:news_id>')
def news_detail(news_id):
    return render_template('news_detail.html', item=News.query.get_or_404(news_id))


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()

        if not (name and email and message):
            flash('Name, email, and message are required.', 'danger')
            return redirect(url_for('contact'))

        db.session.add(ContactMessage(
            name=name, email=email, subject=subject, message=message))
        db.session.commit()
        flash('Thank you! Your message has been sent.', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')


# ============================================================
# MEMBER / STUDENT LOGIN
# ============================================================
@app.route('/member-login', methods=['GET', 'POST'])
def member_login():
    if session.get('super_admin_logged_in'):
        return redirect(url_for('super_admin'))
    if session.get('student_logged_in'):
        return redirect(url_for('src_student'))

    prefill = request.args.get('prefill', '')

    if request.method == 'POST':
        mid = request.form.get('identifier', '').replace('\u00A0', ' ').strip()
        pw = request.form.get('password', '').replace('\u00A0', ' ').strip()

        if mid == SUPER_ADMIN_ID and pw == SUPER_ADMIN_PASSWORD:
            session.clear()
            session['super_admin_logged_in'] = True
            session.permanent = True
            flash('Welcome, Super Admin.', 'success')
            return redirect(url_for('super_admin'))

        student = Student.query.filter(
            db.func.lower(Student.student_id) == mid.lower()).first()

        if student and student.password and check_password_hash(student.password, pw):
            session.clear()
            session['student_logged_in'] = True
            session['student_db_id'] = student.id
            session.permanent = True
            flash(f'Welcome, {student.name}!', 'success')
            return redirect(url_for('src_student'))

        flash('Invalid Member ID or Password. Please try again.', 'danger')

    return render_template('member_login.html', prefill=prefill)


# ============================================================
# SIGNUP
# ============================================================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if session.get('student_logged_in'):
        return redirect(url_for('src_student'))

    year_options = get_year_group_options()
    dob_years = get_dob_years()

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        gender = request.form.get('gender', '').strip()
        student_id = request.form.get('student_id', '').replace('\u00A0', ' ').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        course = request.form.get('course', '').strip()
        dob_d = request.form.get('dob_day', '').strip()
        dob_m = request.form.get('dob_month', '').strip()
        dob_y = request.form.get('dob_year', '').strip()
        level = request.form.get('level', '').strip()
        year_group = request.form.get('year_group', '').strip()
        year_code = request.form.get('year_code', '').strip()

        errors = []
        if not name or len(name) < 2:
            errors.append('Full name is required.')
        if gender not in ('Male', 'Female'):
            errors.append('Please select gender.')
        if not student_id:
            errors.append('ID or phone number is required.')
        if student_id and student_id.lower() in RESERVED_IDS:
            errors.append('That ID is reserved. Please choose another.')
        if len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if password != confirm:
            errors.append('Passwords do not match.')
        if not phone:
            errors.append('Phone number is required.')
        if not course:
            errors.append('Course is required.')

        dob_str = ''
        if not (dob_d and dob_m and dob_y):
            errors.append('Please select your date of birth.')
        else:
            try:
                dob = datetime.strptime(f"{dob_y}-{dob_m.zfill(2)}-{dob_d.zfill(2)}", "%Y-%m-%d")
                age = relativedelta(datetime.utcnow(), dob).years
                if age < 10:
                    errors.append('Date of birth too small — please check.')
                else:
                    dob_str = f"{dob_y}-{dob_m.zfill(2)}-{dob_d.zfill(2)}"
            except ValueError:
                errors.append('Invalid date of birth.')

        if not year_group:
            errors.append('Please select year of completion.')

        if student_id and Student.query.filter(
                db.func.lower(Student.student_id) == student_id.lower()).first():
            errors.append(f'ID "{student_id}" is already taken. Contact administration for support.')

        year_record = YearGroup.query.filter_by(year=year_group).first()
        if not year_record:
            errors.append(f'Year group {year_group} is not open for registration yet. Contact admin.')
        elif year_record.status == 'Completed':
            errors.append(f'Year {year_group} is marked as completed. Please contact admin to sign up.')

        if year_record and year_record.status == 'Active' and level not in ('100', '200', '300', '400'):
            errors.append('Please select your level (100/200/300/400).')

        if year_record and year_code != year_record.code:
            errors.append('Year group password is incorrect.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('signup.html',
                                   year_options=year_options,
                                   dob_years=dob_years,
                                   form=request.form,
                                   show_request_button=True)

        pic = save_upload(request.files.get('profile_pic'))

        student = Student(
            student_id=student_id,
            password=generate_password_hash(password),
            name=name, gender=gender, dob=dob_str, phone=phone,
            email=email, course=course, year_group=year_group, level=level,
            profile_pic=pic, status='Active'
        )
        db.session.add(student)
        db.session.commit()

        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('member_login', prefill=student_id))

    return render_template('signup.html',
                           year_options=year_options, dob_years=dob_years,
                           form={}, show_request_button=False)


@app.route('/signup/request-code', methods=['POST'])
def signup_request_code():
    req = SignupRequest(
        name=request.form.get('name', '').strip(),
        gender=request.form.get('gender', '').strip(),
        student_id=request.form.get('student_id', '').strip(),
        phone=request.form.get('phone', '').strip(),
        course=request.form.get('course', '').strip(),
        dob=request.form.get('dob', '').strip(),
        year_group=request.form.get('year_group', '').strip(),
        level=request.form.get('level', '').strip(),
        message=request.form.get('message', '').strip(),
        status='pending'
    )
    db.session.add(req)
    db.session.commit()
    flash('Your request has been sent to administration. They will contact you.', 'success')
    return redirect(url_for('member_login'))


# ============================================================
# FORGOT PASSWORD
# ============================================================
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    dob_years = get_dob_years()
    student_ref = None

    if request.method == 'POST':
        action = request.form.get('action', '')

        # Both branches require the same identity proof
        sid = request.form.get('student_id', '').replace('\u00A0', ' ').strip()
        dob_d = request.form.get('dob_day', '').strip()
        dob_m = request.form.get('dob_month', '').strip()
        dob_y = request.form.get('dob_year', '').strip()
        year_group = request.form.get('year_group', '').strip()

        student = Student.query.filter(
            db.func.lower(Student.student_id) == sid.lower()).first()

        dob_str = f"{dob_y}-{dob_m.zfill(2)}-{dob_d.zfill(2)}" if (dob_d and dob_m and dob_y) else ''
        identity_ok = bool(student and student.dob == dob_str and student.year_group == year_group)

        if action == 'check':
            if identity_ok:
                flash('Identity confirmed. Enter a new password below.', 'success')
                student_ref = student
            else:
                flash("Oops! We didn't find an account that matches your information. "
                      "Sign up or contact admin for support.", 'danger')

        elif action == 'change_password':
            new_pw = request.form.get('new_password', '')
            confirm = request.form.get('confirm_password', '')

            if not identity_ok:
                flash('Identity could not be verified. Please try again.', 'danger')
            elif len(new_pw) < 6:
                flash('Password must be at least 6 characters.', 'danger')
            elif new_pw != confirm:
                flash('Passwords do not match.', 'danger')
            else:
                student.password = generate_password_hash(new_pw)
                db.session.commit()
                flash('Password updated. Please log in.', 'success')
                return redirect(url_for('member_login', prefill=student.student_id))

    return render_template('forgot_password.html',
                           dob_years=dob_years,
                           student_ref=student_ref)


@app.route('/forgot-password/request-recovery', methods=['POST'])
def request_recovery():
    req = RecoveryRequest(
        name=request.form.get('name', '').strip(),
        student_id=request.form.get('student_id', '').strip(),
        phone=request.form.get('phone', '').strip(),
        year_group=request.form.get('year_group', '').strip(),
        message=request.form.get('message', '').strip(),
        status='pending'
    )
    db.session.add(req)
    db.session.commit()
    flash('Your recovery request has been sent to admin.', 'success')
    return redirect(url_for('member_login'))


# ============================================================
# SRC STUDENT PAGE
# ============================================================
@app.route('/src-student')
@student_required
def src_student():
    student = Student.query.get(session['student_db_id'])

    announcements = Announcement.query \
        .order_by(Announcement.is_pinned.desc(),
                  Announcement.published_at.desc()).all()

    src_president = {
        'name': SiteSetting.get('guest_president_name', 'Ms. Akosua Mensah'),
        'title': SiteSetting.get('guest_president_title', 'SRC President 2025/2026'),
        'photo': SiteSetting.get('guest_president_photo', 'https://i.pravatar.cc/240?img=47'),
    }
    src_principal = {
        'name': SiteSetting.get('guest_principal_name', 'Mrs. Yaa Boateng'),
        'title': SiteSetting.get('guest_principal_title', 'Principal, GNMTC'),
        'photo': SiteSetting.get('guest_principal_photo', 'https://i.pravatar.cc/240?img=32'),
    }

    executives = SRCExecutive.query.order_by(SRCExecutive.order.asc()).all()
    past_presidents = PastLeader.query.filter_by(role='President') \
        .order_by(PastLeader.order.asc()).all()
    past_principals = PastLeader.query.filter_by(role='Principal') \
        .order_by(PastLeader.order.asc()).all()

    year_status = student.year_status()
    can_edit_full = (year_status == 'Active')
    can_edit_limited = (year_status == 'Completed')

    return render_template('src_student.html',
                           student=student,
                           announcements=announcements,
                           src_president=src_president,
                           src_principal=src_principal,
                           executives=executives,
                           past_presidents=past_presidents,
                           past_principals=past_principals,
                           year_status=year_status,
                           can_edit_full=can_edit_full,
                           can_edit_limited=can_edit_limited)


@app.route('/src-student/profile/update', methods=['POST'])
@student_required
def src_student_profile_update():
    student = Student.query.get(session['student_db_id'])
    year_status = student.year_status()

    if year_status == 'Active':
        student.name = request.form.get('name', '').strip() or student.name

        g = request.form.get('gender', '').strip()
        if g in ('Male', 'Female'):
            student.gender = g

        student.dob = request.form.get('dob', '').strip() or student.dob
        student.course = request.form.get('course', '').strip() or student.course

        lvl = request.form.get('level', '').strip()
        if lvl in ('100', '200', '300', '400'):
            student.level = lvl

    new_phone = request.form.get('phone', '').strip()
    if new_phone:
        student.phone = new_phone

    new_pw = request.form.get('new_password', '').strip()
    if new_pw:
        if len(new_pw) < 6:
            flash('New password must be at least 6 characters.', 'danger')
            return redirect(url_for('src_student'))
        student.password = generate_password_hash(new_pw)

    uploaded = save_upload(request.files.get('profile_pic'))
    if uploaded:
        student.profile_pic = uploaded

    db.session.commit()
    flash('Profile updated.', 'success')
    return redirect(url_for('src_student'))


@app.route('/src-student/complaint', methods=['POST'])
@student_required
def src_student_complaint():
    student = Student.query.get(session['student_db_id'])
    subject = request.form.get('subject', '').strip()
    message = request.form.get('message', '').strip()
    if not message:
        flash('Please describe your complaint.', 'danger')
        return redirect(url_for('src_student'))

    db.session.add(Complaint(
        student_id=student.id,
        student_name=student.name,
        student_reg=student.student_id,
        student_phone=student.phone,
        subject=subject,
        message=message,
        status='pending'
    ))
    db.session.commit()
    flash('Complaint sent to administration.', 'success')
    return redirect(url_for('src_student'))


@app.route('/member-logout')
def member_logout():
    session.pop('student_logged_in', None)
    session.pop('student_db_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


# ============================================================
# POLLS
# ============================================================
def _student_voter_key():
    return f"student_{session['student_db_id']}"


@app.route('/polls')
@student_required
def polls_page():
    student = Student.query.get(session['student_db_id'])
    voter_id = _student_voter_key()

    active_polls = Poll.query.filter_by(is_active=True) \
        .order_by(Poll.order.asc(), Poll.created_at.desc()).all()
    polls_data = [build_poll_data(p, voter_id) for p in active_polls]

    year_status = student.year_status()
    can_vote = (year_status == 'Active')

    return render_template('polls.html',
                           student=student,
                           polls=polls_data,
                           can_vote=can_vote,
                           year_status=year_status)


@app.route('/polls/vote', methods=['POST'])
@student_required
def poll_vote():
    student = Student.query.get(session['student_db_id'])

    if student.year_status() == 'Completed':
        return jsonify({'ok': False,
                        'error': 'Your year is completed. Only active students can vote.'}), 403

    try:
        poll_id = int(request.form.get('poll_id', 0))
        option_id = int(request.form.get('option_id', 0))
    except (ValueError, TypeError):
        return jsonify({'ok': False, 'error': 'Invalid data'}), 400

    poll = Poll.query.get(poll_id)
    option = PollOption.query.get(option_id)
    if not poll or not option or option.poll_id != poll.id:
        return jsonify({'ok': False, 'error': 'Poll or option not found'}), 404
    if not poll.is_active:
        return jsonify({'ok': False, 'error': 'This poll is closed'}), 400

    voter_id = _student_voter_key()

    existing = PollVote.query.filter_by(poll_id=poll.id, voter_id=voter_id).first()
    if existing:
        return jsonify({'ok': False, 'error': 'You have already voted in this poll.'}), 409

    db.session.add(PollVote(poll_id=poll.id, option_id=option.id, voter_id=voter_id))
    db.session.commit()
    return jsonify({'ok': True, 'poll': build_poll_data(poll, voter_id)})


@app.route('/polls/request', methods=['POST'])
@student_required
def poll_request():
    student = Student.query.get(session['student_db_id'])
    suggestion = request.form.get('suggestion', '').strip()
    req = PollRequest(
        student_id=student.id,
        student_name=student.name,
        student_reg=student.student_id,
        student_phone=student.phone,
        student_email=student.email or '',
        suggestion=suggestion,
        status='pending'
    )
    db.session.add(req)
    db.session.commit()
    return jsonify({'ok': True, 'request_id': req.id})


# ============================================================
# SUPER ADMIN
# ============================================================
@app.route('/super-admin', methods=['GET', 'POST'])
@admin_required
def super_admin():
    if request.method == 'POST':
        action = request.form.get('action', '')
        _handle_admin_action(action)
        return redirect(url_for('super_admin'))

    search_q = request.args.get('q', '').strip()
    students = []
    if search_q:
        students = Student.query.filter(
            (Student.name.ilike(f'%{search_q}%')) |
            (Student.student_id.ilike(f'%{search_q}%')) |
            (Student.phone.ilike(f'%{search_q}%'))
        ).order_by(Student.name.asc()).all()

    all_students_list = Student.query.order_by(Student.name.asc()).all()

    stats = {
        'members': Student.query.count(),
        'events': Event.query.count(),
        'news': News.query.count(),
        'contributions': Contribution.query.count(),
        'students': Student.query.count(),
    }
    home_title = SiteSetting.get('home_title', 'This is the SRC App for GNMTC')
    home_subtitle = SiteSetting.get('home_subtitle',
        "Goaso Midwifery & Training College — Students' Representative Council")
    home_cards = HomeCard.query.order_by(HomeCard.order.asc()).all()

    about_title = SiteSetting.get('about_title', 'Goaso Midwifery & Training College')
    about_tagline = SiteSetting.get('about_tagline',
        'A story of vision, service, and the training of thousands of midwives for Ghana and beyond.')
    about_history = SiteSetting.get('about_history', DEFAULT_ABOUT_HISTORY)
    about_stats = [
        {'value': SiteSetting.get('about_stat_1_value', '2010'),
         'label': SiteSetting.get('about_stat_1_label', 'Established')},
        {'value': SiteSetting.get('about_stat_2_value', '5,000+'),
         'label': SiteSetting.get('about_stat_2_label', 'Midwives & Nurses Trained')},
        {'value': SiteSetting.get('about_stat_3_value', '~900'),
         'label': SiteSetting.get('about_stat_3_label', 'Current Students')},
        {'value': SiteSetting.get('about_stat_4_value', '50+'),
         'label': SiteSetting.get('about_stat_4_label', 'Staff Members')},
    ]
    about_people = AboutPerson.query.order_by(AboutPerson.order.asc()).all()
    footer_about = SiteSetting.get('footer_about',
        "Goaso Midwifery and Training College — training compassionate, "
        "competent midwives for Ghana and beyond since December 2010.")

    guest_settings = get_guest_settings()
    guest_admins = GuestAdmin.query.order_by(GuestAdmin.order.asc()).all()
    gallery_images = GalleryImage.query.order_by(GalleryImage.order.asc()).all()

    announcements = Announcement.query \
        .order_by(Announcement.is_pinned.desc(),
                  Announcement.published_at.desc()).all()

    all_polls = Poll.query.order_by(Poll.order.asc(), Poll.created_at.desc()).all()
    polls_admin = []
    for p in all_polls:
        total = PollVote.query.filter_by(poll_id=p.id).count()
        options = []
        for opt in p.options:
            cnt = PollVote.query.filter_by(poll_id=p.id, option_id=opt.id).count()
            pct = round((cnt / total * 100), 1) if total > 0 else 0
            options.append({'id': opt.id, 'name': opt.name, 'image': opt.image,
                            'count': cnt, 'percent': pct})
        polls_admin.append({
            'id': p.id, 'question': p.question, 'description': p.description,
            'is_active': p.is_active, 'total_votes': total,
            'options': options, 'created_at': p.created_at,
        })

    executives = SRCExecutive.query.order_by(SRCExecutive.order.asc()).all()
    past_presidents = PastLeader.query.filter_by(role='President') \
        .order_by(PastLeader.order.asc()).all()
    past_principals = PastLeader.query.filter_by(role='Principal') \
        .order_by(PastLeader.order.asc()).all()

    year_groups = YearGroup.query.order_by(YearGroup.year.asc()).all()

    signup_requests = SignupRequest.query.order_by(SignupRequest.created_at.desc()).all()
    recovery_requests = RecoveryRequest.query.order_by(RecoveryRequest.created_at.desc()).all()
    complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()
    poll_requests = PollRequest.query.order_by(PollRequest.created_at.desc()).all()

    return render_template('super_admin.html',
                           stats=stats,
                           search_q=search_q,
                           students=students,
                           all_students_list=all_students_list,
                           home_title=home_title, home_subtitle=home_subtitle,
                           home_cards=home_cards,
                           about_title=about_title, about_tagline=about_tagline,
                           about_history=about_history, about_stats=about_stats,
                           about_people=about_people, footer_about=footer_about,
                           guest_settings=guest_settings, guest_admins=guest_admins,
                           gallery_images=gallery_images,
                           announcements=announcements, polls=polls_admin,
                           executives=executives,
                           past_presidents=past_presidents,
                           past_principals=past_principals,
                           year_groups=year_groups,
                           signup_requests=signup_requests,
                           recovery_requests=recovery_requests,
                           complaints=complaints,
                           poll_requests=poll_requests)


def _handle_admin_action(action):
    """All admin POST actions handled here."""
    handlers = {
        'save_title': _action_save_title,
        'add_card': _action_add_card,
        'update_card': _action_update_card,
        'delete_card': _action_delete_card,
        'save_about_text': _action_save_about_text,
        'save_about_stats': _action_save_about_stats,
        'add_about_person': _action_add_about_person,
        'update_about_person': _action_update_about_person,
        'delete_about_person': _action_delete_about_person,
        'save_footer_about': _action_save_footer_about,
        'save_guest_hero': _action_save_guest_hero,
        'save_guest_about': _action_save_guest_about,
        'save_guest_contact': _action_save_guest_contact,
        'add_guest_admin': _action_add_guest_admin,
        'update_guest_admin': _action_update_guest_admin,
        'delete_guest_admin': _action_delete_guest_admin,
        'add_gallery_image': _action_add_gallery_image,
        'update_gallery_image': _action_update_gallery_image,
        'delete_gallery_image': _action_delete_gallery_image,
        'add_announcement': _action_add_announcement,
        'update_announcement': _action_update_announcement,
        'delete_announcement': _action_delete_announcement,
        'add_executive': _action_add_executive,
        'update_executive': _action_update_executive,
        'delete_executive': _action_delete_executive,
        'add_past_leader': _action_add_past_leader,
        'update_past_leader': _action_update_past_leader,
        'delete_past_leader': _action_delete_past_leader,
        'add_year_group': _action_add_year_group,
        'update_year_group': _action_update_year_group,
        'delete_year_group': _action_delete_year_group,
        'update_student': _action_update_student,
        'delete_student': _action_delete_student,
        'resolve_signup_request': _action_resolve_signup_request,
        'delete_signup_request': _action_delete_signup_request,
        'resolve_recovery_request': _action_resolve_recovery_request,
        'delete_recovery_request': _action_delete_recovery_request,
        'resolve_complaint': _action_resolve_complaint,
        'delete_complaint': _action_delete_complaint,
        'resolve_poll_request': _action_resolve_poll_request,
        'decline_poll_request': _action_decline_poll_request,
        'delete_poll_request': _action_delete_poll_request,
        'add_poll': _action_add_poll,
        'toggle_poll': _action_toggle_poll,
        'delete_poll': _action_delete_poll,
    }
    handler = handlers.get(action)
    if not handler:
        app.logger.warning(f"Unknown admin action: {action!r}")
        flash(f'Unknown action: {action}', 'danger')
        return
    handler()


# ---------- ACTION IMPLEMENTATIONS ----------
def _action_save_title():
    SiteSetting.set('home_title', request.form.get('home_title', '').strip())
    SiteSetting.set('home_subtitle', request.form.get('home_subtitle', '').strip())
    db.session.commit()
    flash('Home page title updated.', 'success')


def _action_add_card():
    fn = save_upload(request.files.get('image'))
    order = (HomeCard.query.count() or 0) + 1
    db.session.add(HomeCard(
        eyebrow=request.form.get('eyebrow', '').strip(),
        title=request.form.get('title', '').strip(),
        description=request.form.get('description', '').strip(),
        image=fn, order=order))
    db.session.commit()
    flash('Card added.', 'success')


def _action_update_card():
    card = HomeCard.query.get(_int('card_id'))
    if card:
        card.eyebrow = request.form.get('eyebrow', '').strip()
        card.title = request.form.get('title', '').strip()
        card.description = request.form.get('description', '').strip()
        uploaded = save_upload(request.files.get('image'))
        url_value = request.form.get('image_url', '').strip()
        if uploaded:
            card.image = uploaded
        elif url_value and url_value != card.image:
            card.image = url_value
        db.session.commit()
        flash('Card updated.', 'success')


def _action_delete_card():
    card = HomeCard.query.get(_int('card_id'))
    if card:
        db.session.delete(card)
        db.session.commit()
        flash('Card deleted.', 'success')


def _action_save_about_text():
    SiteSetting.set('about_title', request.form.get('about_title', '').strip())
    SiteSetting.set('about_tagline', request.form.get('about_tagline', '').strip())
    SiteSetting.set('about_history', request.form.get('about_history', '').strip())
    db.session.commit()
    flash('About page text updated.', 'success')


def _action_save_about_stats():
    for i in range(1, 5):
        SiteSetting.set(f'about_stat_{i}_value',
                        request.form.get(f'about_stat_{i}_value', '').strip())
        SiteSetting.set(f'about_stat_{i}_label',
                        request.form.get(f'about_stat_{i}_label', '').strip())
    db.session.commit()
    flash('About page stats updated.', 'success')


def _action_add_about_person():
    db.session.add(AboutPerson(
        name=request.form.get('name', '').strip(),
        role=request.form.get('role', '').strip(),
        note=request.form.get('note', '').strip(),
        icon=request.form.get('icon', '🎓').strip() or '🎓',
        order=(AboutPerson.query.count() or 0) + 1))
    db.session.commit()
    flash('Person added.', 'success')


def _action_update_about_person():
    p = AboutPerson.query.get(_int('person_id'))
    if p:
        p.name = request.form.get('name', '').strip()
        p.role = request.form.get('role', '').strip()
        p.note = request.form.get('note', '').strip()
        p.icon = request.form.get('icon', '🎓').strip() or '🎓'
        db.session.commit()
        flash('Person updated.', 'success')


def _action_delete_about_person():
    p = AboutPerson.query.get(_int('person_id'))
    if p:
        db.session.delete(p)
        db.session.commit()
        flash('Person removed.', 'success')


def _action_save_footer_about():
    SiteSetting.set('footer_about', request.form.get('footer_about', '').strip())
    db.session.commit()
    flash('Footer About text updated.', 'success')


def _action_save_guest_hero():
    for key in ['guest_president_name', 'guest_president_title',
                'guest_principal_name', 'guest_principal_title']:
        SiteSetting.set(key, request.form.get(key, '').strip())

    current = SiteSetting.get('guest_president_photo', '')
    uploaded = save_upload(request.files.get('president_photo'))
    url_value = request.form.get('president_photo_url', '').strip()
    if uploaded:
        SiteSetting.set('guest_president_photo', uploaded)
    elif url_value and url_value != current:
        SiteSetting.set('guest_president_photo', url_value)

    current = SiteSetting.get('guest_principal_photo', '')
    uploaded = save_upload(request.files.get('principal_photo'))
    url_value = request.form.get('principal_photo_url', '').strip()
    if uploaded:
        SiteSetting.set('guest_principal_photo', uploaded)
    elif url_value and url_value != current:
        SiteSetting.set('guest_principal_photo', url_value)

    db.session.commit()
    flash('Guest hero updated.', 'success')


def _action_save_guest_about():
    for key in ['guest_about', 'guest_aim', 'guest_ambition']:
        SiteSetting.set(key, request.form.get(key, '').strip())
    SiteSetting.set('guest_courses', request.form.get('guest_courses', '').strip())
    db.session.commit()
    flash('Guest about updated.', 'success')


def _action_save_guest_contact():
    for key in ['guest_location', 'guest_email', 'guest_website',
                'guest_phone', 'guest_whatsapp', 'guest_gallery_heading']:
        SiteSetting.set(key, request.form.get(key, '').strip())
    db.session.commit()
    flash('Guest contact info updated.', 'success')


def _action_add_guest_admin():
    uploaded = save_upload(request.files.get('photo'))
    url_value = request.form.get('photo_url', '').strip()
    db.session.add(GuestAdmin(
        name=request.form.get('name', '').strip(),
        role=request.form.get('role', '').strip(),
        photo=uploaded or url_value or None,
        order=(GuestAdmin.query.count() or 0) + 1))
    db.session.commit()
    flash('Administrator added.', 'success')


def _action_update_guest_admin():
    a = GuestAdmin.query.get(_int('admin_id'))
    if a:
        a.name = request.form.get('name', '').strip()
        a.role = request.form.get('role', '').strip()
        uploaded = save_upload(request.files.get('photo'))
        url_value = request.form.get('photo_url', '').strip()
        if uploaded:
            a.photo = uploaded
        elif url_value and url_value != a.photo:
            a.photo = url_value
        db.session.commit()
        flash('Administrator updated.', 'success')


def _action_delete_guest_admin():
    a = GuestAdmin.query.get(_int('admin_id'))
    if a:
        db.session.delete(a)
        db.session.commit()
        flash('Administrator removed.', 'success')


def _action_add_gallery_image():
    uploaded = save_upload(request.files.get('image'))
    url_value = request.form.get('image_url', '').strip()
    final = uploaded or url_value
    if final:
        db.session.add(GalleryImage(
            image=final,
            caption=request.form.get('caption', '').strip(),
            order=(GalleryImage.query.count() or 0) + 1))
        db.session.commit()
        flash('Gallery image added.', 'success')
    else:
        flash('Upload an image or provide a URL.', 'danger')


def _action_update_gallery_image():
    g = GalleryImage.query.get(_int('image_id'))
    if g:
        g.caption = request.form.get('caption', '').strip()
        uploaded = save_upload(request.files.get('image'))
        url_value = request.form.get('image_url', '').strip()
        if uploaded:
            g.image = uploaded
        elif url_value and url_value != g.image:
            g.image = url_value
        db.session.commit()
        flash('Gallery image updated.', 'success')


def _action_delete_gallery_image():
    g = GalleryImage.query.get(_int('image_id'))
    if g:
        db.session.delete(g)
        db.session.commit()
        flash('Gallery image removed.', 'success')


def _action_add_announcement():
    title = request.form.get('title', '').strip()
    body = request.form.get('body', '').strip()
    if title and body:
        fn, orig = save_doc(request.files.get('file'))
        db.session.add(Announcement(
            title=title, body=body,
            category=request.form.get('category', 'General').strip() or 'General',
            file=fn, file_name=orig,
            is_pinned='is_pinned' in request.form))
        db.session.commit()
        flash('Announcement posted.', 'success')
    else:
        flash('Title and body are required.', 'danger')


def _action_update_announcement():
    a = Announcement.query.get(_int('announcement_id'))
    if a:
        a.title = request.form.get('title', '').strip()
        a.body = request.form.get('body', '').strip()
        a.category = request.form.get('category', 'General').strip() or 'General'
        a.is_pinned = 'is_pinned' in request.form
        fn, orig = save_doc(request.files.get('file'))
        if fn:
            a.file = fn
            a.file_name = orig
        db.session.commit()
        flash('Announcement updated.', 'success')


def _action_delete_announcement():
    a = Announcement.query.get(_int('announcement_id'))
    if a:
        db.session.delete(a)
        db.session.commit()
        flash('Announcement deleted.', 'success')


def _action_add_executive():
    uploaded = save_upload(request.files.get('photo'))
    db.session.add(SRCExecutive(
        name=request.form.get('name', '').strip(),
        position=request.form.get('position', '').strip(),
        photo=uploaded or None,
        order=(SRCExecutive.query.count() or 0) + 1))
    db.session.commit()
    flash('Executive added.', 'success')


def _action_update_executive():
    ex = SRCExecutive.query.get(_int('exec_id'))
    if ex:
        ex.name = request.form.get('name', '').strip()
        ex.position = request.form.get('position', '').strip()
        uploaded = save_upload(request.files.get('photo'))
        if uploaded:
            ex.photo = uploaded
        db.session.commit()
        flash('Executive updated.', 'success')


def _action_delete_executive():
    ex = SRCExecutive.query.get(_int('exec_id'))
    if ex:
        db.session.delete(ex)
        db.session.commit()
        flash('Executive removed.', 'success')


def _action_add_past_leader():
    uploaded = save_upload(request.files.get('photo'))
    db.session.add(PastLeader(
        name=request.form.get('name', '').strip(),
        role=request.form.get('role', 'President').strip(),
        years=request.form.get('years', '').strip(),
        photo=uploaded or None,
        order=(PastLeader.query.count() or 0) + 1))
    db.session.commit()
    flash('Past leader added.', 'success')


def _action_update_past_leader():
    pl = PastLeader.query.get(_int('leader_id'))
    if pl:
        pl.name = request.form.get('name', '').strip()
        pl.role = request.form.get('role', 'President').strip()
        pl.years = request.form.get('years', '').strip()
        uploaded = save_upload(request.files.get('photo'))
        if uploaded:
            pl.photo = uploaded
        db.session.commit()
        flash('Past leader updated.', 'success')


def _action_delete_past_leader():
    pl = PastLeader.query.get(_int('leader_id'))
    if pl:
        db.session.delete(pl)
        db.session.commit()
        flash('Past leader removed.', 'success')


def _action_add_year_group():
    year = request.form.get('year', '').strip()
    code = request.form.get('code', '').strip()
    status = request.form.get('status', 'Active').strip()
    if not year or not code:
        flash('Year and code are required.', 'danger')
    elif YearGroup.query.filter_by(year=year).first():
        flash(f'Year {year} already exists.', 'danger')
    else:
        db.session.add(YearGroup(
            year=year, code=code,
            status=status if status in ('Active', 'Completed') else 'Active'))
        db.session.commit()
        flash(f'Year group {year} added.', 'success')


def _action_update_year_group():
    yg = YearGroup.query.get(_int('year_id'))
    if yg:
        new_year = request.form.get('year', '').strip()
        if new_year and new_year != yg.year:
            if YearGroup.query.filter_by(year=new_year).first():
                flash(f'Year {new_year} already exists.', 'danger')
                return
            yg.year = new_year
        yg.code = request.form.get('code', yg.code).strip() or yg.code
        new_status = request.form.get('status', 'Active').strip()
        if new_status in ('Active', 'Completed'):
            yg.status = new_status
        db.session.commit()
        flash('Year group updated.', 'success')


def _action_delete_year_group():
    yg = YearGroup.query.get(_int('year_id'))
    if yg:
        in_use = Student.query.filter_by(year_group=yg.year).count()
        if in_use:
            flash(f'Cannot delete {yg.year} — {in_use} student(s) still assigned.', 'danger')
        else:
            db.session.delete(yg)
            db.session.commit()
            flash('Year group deleted.', 'success')


def _action_update_student():
    s = Student.query.get(_int('student_db_id'))
    if not s:
        return
    new_sid = request.form.get('student_id', s.student_id).strip()
    if new_sid.lower() in RESERVED_IDS:
        flash('That ID is reserved.', 'danger')
        return
    if new_sid.lower() != s.student_id.lower():
        if Student.query.filter(db.func.lower(Student.student_id) == new_sid.lower()).first():
            flash(f'ID "{new_sid}" already taken.', 'danger')
            return
        s.student_id = new_sid

    s.name = request.form.get('name', s.name).strip() or s.name
    s.gender = request.form.get('gender', s.gender).strip() or s.gender
    s.dob = request.form.get('dob', s.dob).strip() or s.dob
    s.phone = request.form.get('phone', s.phone).strip()
    s.email = request.form.get('email', s.email).strip()
    s.course = request.form.get('course', s.course).strip()
    s.year_group = request.form.get('year_group', s.year_group).strip()
    s.level = request.form.get('level', s.level).strip()
    s.status = request.form.get('status', s.status).strip() or s.status

    new_pw = request.form.get('password', '').strip()
    if new_pw and len(new_pw) >= 4:
        s.password = generate_password_hash(new_pw)

    uploaded = save_upload(request.files.get('profile_pic'))
    if uploaded:
        s.profile_pic = uploaded

    db.session.commit()
    flash('Student updated.', 'success')


def _action_delete_student():
    s = Student.query.get(_int('student_db_id'))
    if not s:
        return
    PollVote.query.filter_by(voter_id=f"student_{s.id}").delete()
    Complaint.query.filter_by(student_id=s.id).update({'student_id': None})
    PollRequest.query.filter_by(student_id=s.id).update({'student_id': None})
    db.session.delete(s)
    db.session.commit()
    flash('Student removed.', 'success')


def _action_resolve_signup_request():
    r = SignupRequest.query.get(_int('request_id'))
    if r:
        r.status = 'resolved'
        db.session.commit()
        flash('Signup request resolved.', 'success')


def _action_delete_signup_request():
    r = SignupRequest.query.get(_int('request_id'))
    if r:
        db.session.delete(r)
        db.session.commit()
        flash('Signup request deleted.', 'success')


def _action_resolve_recovery_request():
    r = RecoveryRequest.query.get(_int('request_id'))
    if r:
        r.status = 'resolved'
        db.session.commit()
        flash('Recovery request resolved.', 'success')


def _action_delete_recovery_request():
    r = RecoveryRequest.query.get(_int('request_id'))
    if r:
        db.session.delete(r)
        db.session.commit()
        flash('Recovery request deleted.', 'success')


def _action_resolve_complaint():
    c = Complaint.query.get(_int('complaint_id'))
    if c:
        c.status = 'resolved'
        db.session.commit()
        flash('Complaint resolved.', 'success')


def _action_delete_complaint():
    c = Complaint.query.get(_int('complaint_id'))
    if c:
        db.session.delete(c)
        db.session.commit()
        flash('Complaint deleted.', 'success')


def _action_resolve_poll_request():
    r = PollRequest.query.get(_int('request_id'))
    if r:
        r.status = 'approved'
        db.session.commit()
        flash('Poll request approved.', 'success')


def _action_decline_poll_request():
    r = PollRequest.query.get(_int('request_id'))
    if r:
        r.status = 'declined'
        db.session.commit()
        flash('Poll request declined.', 'success')


def _action_delete_poll_request():
    r = PollRequest.query.get(_int('request_id'))
    if r:
        db.session.delete(r)
        db.session.commit()
        flash('Poll request deleted.', 'success')


def _action_add_poll():
    question = request.form.get('question', '').strip()
    if not question:
        flash('Poll question is required.', 'danger')
        return

    p = Poll(question=question,
             description=request.form.get('description', '').strip(),
             is_active='is_active' in request.form,
             order=(Poll.query.count() or 0) + 1)
    db.session.add(p)
    db.session.commit()

    names = request.form.getlist('option_name')
    images = request.files.getlist('option_image')
    urls = request.form.getlist('option_image_url')
    for i, name in enumerate(names):
        name = (name or '').strip()
        if not name:
            continue
        img_final = None
        if i < len(images):
            img_final = save_upload(images[i])
        if not img_final and i < len(urls):
            img_final = (urls[i] or '').strip() or None
        db.session.add(PollOption(poll_id=p.id, name=name,
                                  image=img_final, order=i + 1))
    db.session.commit()
    flash('Poll created.', 'success')


def _action_toggle_poll():
    p = Poll.query.get(_int('poll_id'))
    if p:
        p.is_active = not p.is_active
        db.session.commit()
        flash('Poll status updated.', 'success')


def _action_delete_poll():
    p = Poll.query.get(_int('poll_id'))
    if p:
        db.session.delete(p)
        db.session.commit()
        flash('Poll deleted.', 'success')


@app.route('/super-admin-logout')
def super_admin_logout():
    session.pop('super_admin_logged_in', None)
    flash('Super Admin session ended.', 'info')
    return redirect(url_for('index'))


# ============================================================
# FILE DOWNLOAD
# ============================================================
@app.route('/download/<path:filename>')
def download_file(filename):
    if not (session.get('student_logged_in') or session.get('super_admin_logged_in')):
        flash('Please log in to download files.', 'info')
        return redirect(url_for('member_login'))

    if is_remote(filename):
        return redirect(filename)

    safe = os.path.basename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], safe, as_attachment=True)


# ============================================================
# ALUMNI AUTH (legacy)
# ============================================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        user = User(
            full_name=request.form['full_name'], email=email,
            graduation_year=request.form.get('graduation_year', ''),
            program=request.form.get('program', ''),
            phone=request.form.get('phone', ''),
            occupation=request.form.get('occupation', ''),
            location=request.form.get('location', ''),
            bio=request.form.get('bio', ''), is_admin=False)
        user.set_password(request.form['password'])
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember='remember' in request.form)
            flash(f'Welcome back, {user.full_name}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    my_payments = Payment.query.filter_by(user_id=current_user.id).all()
    total_paid = sum(p.amount for p in my_payments if p.status == 'confirmed')
    pending = sum(p.amount for p in my_payments if p.status == 'pending')
    active = Contribution.query.filter_by(is_active=True).all()
    total_expected = sum(c.amount for c in active)
    outstanding = max(total_expected - total_paid, 0)
    payment_summary = {'total_paid': total_paid, 'pending': pending,
                       'outstanding': outstanding}
    return render_template('dashboard.html', payment_summary=payment_summary)


@app.route('/contributions')
@login_required
def contributions():
    items = Contribution.query.order_by(Contribution.created_at.desc()).all()
    user_status = {}
    for c in items:
        paid = sum(p.amount for p in c.payments
                   if p.user_id == current_user.id and p.status == 'confirmed')
        pending = sum(p.amount for p in c.payments
                      if p.user_id == current_user.id and p.status == 'pending')
        user_status[c.id] = {
            'paid': paid, 'pending': pending,
            'outstanding': max(c.amount - paid, 0),
            'percent': min(int((paid / c.amount) * 100), 100) if c.amount else 0,
        }
    return render_template('contributions.html',
                           contributions=items, status=user_status)


@app.route('/contributions/<int:cid>')
@login_required
def contribution_detail(cid):
    c = Contribution.query.get_or_404(cid)
    my_payments = Payment.query.filter_by(
        user_id=current_user.id, contribution_id=cid
    ).order_by(Payment.paid_at.desc()).all()
    paid = sum(p.amount for p in my_payments if p.status == 'confirmed')
    pending = sum(p.amount for p in my_payments if p.status == 'pending')
    return render_template('contribution_detail.html',
                           c=c, payments=my_payments, paid=paid, pending=pending,
                           outstanding=max(c.amount - paid, 0))


@app.route('/contributions/<int:cid>/pay', methods=['POST'])
@login_required
def submit_payment(cid):
    c = Contribution.query.get_or_404(cid)
    try:
        amount = float(request.form.get('amount', 0))
    except ValueError:
        amount = 0
    if amount <= 0:
        flash('Please enter a valid amount.', 'danger')
        return redirect(url_for('contribution_detail', cid=cid))
    receipt = Payment.generate_receipt()
    p = Payment(user_id=current_user.id, contribution_id=cid, amount=amount,
                method=request.form.get('method', 'Mobile Money'),
                reference=request.form.get('reference', '').strip(),
                note=request.form.get('note', '').strip(),
                status='pending', receipt_no=receipt)
    db.session.add(p)
    db.session.commit()
    flash(f'Payment submitted! Reference: {receipt}.', 'success')
    return redirect(url_for('contribution_detail', cid=cid))


@app.route('/my-payments')
@login_required
def my_payments():
    payments = Payment.query.filter_by(user_id=current_user.id) \
        .order_by(Payment.paid_at.desc()).all()
    total_paid = sum(p.amount for p in payments if p.status == 'confirmed')
    total_pending = sum(p.amount for p in payments if p.status == 'pending')
    return render_template('my_payments.html',
                           payments=payments, total_paid=total_paid,
                           total_pending=total_pending)


# ============================================================
# STARTUP
# ============================================================
with app.app_context():
    try:
        db.create_all()

        # YEAR GROUPS — dynamic, current year and future are Active
        if YearGroup.query.count() == 0:
            current_year = datetime.utcnow().year
            for y in range(2010, current_year + 5):
                status = 'Active' if y >= current_year else 'Completed'
                db.session.add(YearGroup(year=str(y), code=f"01{str(y)[-2:]}", status=status))
            db.session.commit()

        # STUDENTS — hashed passwords
        if Student.query.count() == 0:
            if not Student.query.filter_by(student_id='0987654321').first():
                db.session.add(Student(
                    student_id='0987654321',
                    password=generate_password_hash('1234567890'),
                    name='Ama Serwaa Boateng',
                    gender='Female', dob='2000-05-15',
                    status='Active', phone='+233 24 000 0000',
                    email='ama.boateng@gnmtc.edu.gh',
                    course='Registered Midwifery',
                    year_group='2027', level='200',
                    profile_pic='https://i.pravatar.cc/240?img=47'))
            if not Student.query.filter_by(student_id='ophyser').first():
                db.session.add(Student(
                    student_id='ophyser',
                    password=generate_password_hash('Klinsman@ophyser1'),
                    name='Ophyser Mensah',
                    gender='Male', dob='1998-08-22',
                    status='Active', phone='+233 24 111 1111',
                    email='ophyser@gnmtc.edu.gh',
                    course='Registered General Nursing',
                    year_group='2027', level='300',
                    profile_pic='https://i.pravatar.cc/240?img=12'))
            db.session.commit()

        # HOME CARDS
        if HomeCard.query.count() == 0:
            for d in [
                HomeCard(eyebrow='News', title='Latest from the SRC',
                         description="Stay updated with announcements, exam timetables, and important notices.",
                         image='https://images.unsplash.com/photo-1576091160550-2173dba999ef?auto=format&fit=crop&w=800&q=80', order=1),
                HomeCard(eyebrow='Events', title='Upcoming Activities',
                         description='Reunions, CPD workshops, and social events happening at Goaso Midwifery.',
                         image='https://images.unsplash.com/photo-1523240795612-9a054b0db644?auto=format&fit=crop&w=800&q=80', order=2),
                HomeCard(eyebrow='Academics', title='Study Resources',
                         description='Access lecture notes, past questions, and reference materials.',
                         image='https://images.unsplash.com/photo-1584515933487-779824d29309?auto=format&fit=crop&w=800&q=80', order=3),
                HomeCard(eyebrow='Community', title='Our Alumni Network',
                         description='Connect with graduates across Ghana.',
                         image='https://images.unsplash.com/photo-1519494026892-80bbd2d6fd0d?auto=format&fit=crop&w=800&q=80', order=4),
            ]:
                db.session.add(d)
            db.session.commit()

        # ABOUT PEOPLE
        if AboutPerson.query.count() == 0:
            for p in [
                AboutPerson(name='Hon. Mohammed Kwaku Doku', role='Municipal Chief Executive (then)',
                            note='Championed the establishment of the school.', icon='🏛️', order=1),
                AboutPerson(name='Nana Kwasi Baffour Bosompra', role='Late Omanhene, Goaso Traditional Area',
                            note='Royal support and vision.', icon='👑', order=2),
                AboutPerson(name='Presby Church of Ghana', role='Trinity Congregation, Goaso',
                            note='Donated the first campus.', icon='⛪', order=3),
                AboutPerson(name='Hajia Halima Opoku Ahmed', role='Former Principal',
                            note='Led the college from inception.', icon='🎓', order=4),
                AboutPerson(name='Mr. Samuel Ansu Frimpong', role='Former Principal',
                            note='Guided the college growth.', icon='🎓', order=5),
            ]:
                db.session.add(p)
            db.session.commit()

        # GUEST ADMINS
        if GuestAdmin.query.count() == 0:
            for a in [
                GuestAdmin(name='Mrs. Yaa Boateng', role='Principal', order=1),
                GuestAdmin(name='Mr. Kwame Asante', role='Vice Principal', order=2),
                GuestAdmin(name='Ms. Adwoa Owusu', role='Academic Head', order=3),
                GuestAdmin(name='Mr. Yaw Darko', role='Registrar', order=4),
                GuestAdmin(name='Ms. Esi Appiah', role='Dean of Students', order=5),
                GuestAdmin(name='Mr. Kofi Mensah', role='SRC Coordinator', order=6),
            ]:
                db.session.add(a)
            db.session.commit()

        # GALLERY
        if GalleryImage.query.count() == 0:
            for i, url in enumerate([
                'https://images.unsplash.com/photo-1576091160399-112ba8d25d1d?auto=format&fit=crop&w=600&q=80',
                'https://images.unsplash.com/photo-1631217868264-e5b90bb7e133?auto=format&fit=crop&w=600&q=80',
                'https://images.unsplash.com/photo-1579684385127-1ef15d508118?auto=format&fit=crop&w=600&q=80',
                'https://images.unsplash.com/photo-1584515933487-779824d29309?auto=format&fit=crop&w=600&q=80',
                'https://images.unsplash.com/photo-1519494026892-80bbd2d6fd0d?auto=format&fit=crop&w=600&q=80',
                'https://images.unsplash.com/photo-1532938911079-1b06ac7ceec7?auto=format&fit=crop&w=600&q=80',
            ], start=1):
                db.session.add(GalleryImage(image=url, caption='', order=i))
            db.session.commit()

        # ANNOUNCEMENTS
        if Announcement.query.count() == 0:
            db.session.add(Announcement(
                title='Welcome to the SRC Student Portal',
                body=("Welcome, students of Goaso Midwifery & Training College!\n\n"
                      "This is your official SRC notice board."),
                category='General', is_pinned=True))
            db.session.commit()

        # POLLS
        if Poll.query.count() == 0:
            p1 = Poll(question="Who is winning the SRC President election?",
                      description="SRC Election 2025/2026 — cast your vote.",
                      is_active=True, order=1)
            db.session.add(p1)
            db.session.commit()
            for i, (name, img) in enumerate([
                ('Kusi Boateng', 'https://i.pravatar.cc/200?img=12'),
                ('Kyei Mensah', 'https://i.pravatar.cc/200?img=33'),
                ('Akosua Serwaa', 'https://i.pravatar.cc/200?img=47'),
            ], start=1):
                db.session.add(PollOption(poll_id=p1.id, name=name, image=img, order=i))

            p2 = Poll(question="Who is winning the Treasurer election?",
                      description="SRC Election 2025/2026 — Treasurer position.",
                      is_active=True, order=2)
            db.session.add(p2)
            db.session.commit()
            for i, (name, img) in enumerate([
                ('Adwoa Owusu', 'https://i.pravatar.cc/200?img=45'),
                ('Esi Appiah', 'https://i.pravatar.cc/200?img=48'),
                ('Yaw Darko', 'https://i.pravatar.cc/200?img=15'),
            ], start=1):
                db.session.add(PollOption(poll_id=p2.id, name=name, image=img, order=i))
            db.session.commit()

        # EXECUTIVES
        if SRCExecutive.query.count() == 0:
            for ex in [
                {'name': 'Mr. Kwame Asante', 'position': 'Board Treasurer',
                 'photo': 'https://i.pravatar.cc/200?img=12'},
                {'name': 'Ms. Adwoa Owusu', 'position': 'SRC Secretary',
                 'photo': 'https://i.pravatar.cc/200?img=45'},
                {'name': "Ms. Esi Appiah", 'position': "Women's Commissioner",
                 'photo': 'https://i.pravatar.cc/200?img=48'},
                {'name': 'Mr. Yaw Darko', 'position': 'Organizer',
                 'photo': 'https://i.pravatar.cc/200?img=15'},
                {'name': 'Mr. Kofi Mensah', 'position': 'SRC Vice President',
                 'photo': 'https://i.pravatar.cc/200?img=33'},
                {'name': 'Ms. Akua Mensah', 'position': 'Public Relations Officer',
                 'photo': 'https://i.pravatar.cc/200?img=20'},
                {'name': 'Mr. Nana Boateng', 'position': 'Sports Director',
                 'photo': 'https://i.pravatar.cc/200?img=11'},
                {'name': 'Ms. Comfort Owusu', 'position': 'Welfare Officer',
                 'photo': 'https://i.pravatar.cc/200?img=26'},
                {'name': 'Mr. Isaac Adjei', 'position': 'Academic Committee Head',
                 'photo': 'https://i.pravatar.cc/200?img=59'},
            ]:
                db.session.add(SRCExecutive(
                    order=(SRCExecutive.query.count() or 0) + 1, **ex))
            db.session.commit()

        # PAST LEADERS
        if PastLeader.query.count() == 0:
            for pl in [
                {'name': 'Mr. Samuel Osei', 'role': 'President', 'years': '2023/2024',
                 'photo': 'https://i.pravatar.cc/200?img=11'},
                {'name': 'Ms. Grace Boateng', 'role': 'President', 'years': '2022/2023',
                 'photo': 'https://i.pravatar.cc/200?img=24'},
                {'name': 'Mr. Daniel Appiah', 'role': 'President', 'years': '2021/2022',
                 'photo': 'https://i.pravatar.cc/200?img=52'},
                {'name': 'Ms. Comfort Mensah', 'role': 'President', 'years': '2020/2021',
                 'photo': 'https://i.pravatar.cc/200?img=26'},
                {'name': 'Mrs. Mary Aidoo', 'role': 'Principal', 'years': '2015 – 2020',
                 'photo': 'https://i.pravatar.cc/200?img=20'},
                {'name': 'Mr. Joseph Nyarko', 'role': 'Principal', 'years': '2010 – 2015',
                 'photo': 'https://i.pravatar.cc/200?img=13'},
            ]:
                db.session.add(PastLeader(
                    order=(PastLeader.query.count() or 0) + 1, **pl))
            db.session.commit()

        app.logger.info("✅ Database initialized successfully.")

    except Exception as e:
        app.logger.error(f"⚠️ Database startup error: {e}")


if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
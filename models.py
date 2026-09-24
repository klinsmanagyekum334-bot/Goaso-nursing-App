import secrets
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# ============================================================
# SITE SETTINGS (key/value store)
# ============================================================
class SiteSetting(db.Model):
    __tablename__ = 'site_setting'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, default='')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @classmethod
    def get(cls, key, default=None):
        row = cls.query.filter_by(key=key).first()
        if row is None:
            return default
        return row.value if row.value is not None else default

    @classmethod
    def set(cls, key, value):
        """Set a key. Caller must call db.session.commit()."""
        row = cls.query.filter_by(key=key).first()
        if row is None:
            row = cls(key=key, value=value or '')
            db.session.add(row)
        else:
            row.value = value or ''
        return row


# ============================================================
# LEGACY ALUMNI USER (Flask-Login)
# ============================================================
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    graduation_year = db.Column(db.String(10), default='')
    program = db.Column(db.String(120), default='')
    phone = db.Column(db.String(40), default='')
    occupation = db.Column(db.String(120), default='')
    location = db.Column(db.String(120), default='')
    bio = db.Column(db.Text, default='')
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    payments = db.relationship('Payment', backref='user', lazy=True,
                               cascade='all, delete-orphan')

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw)


# ============================================================
# STUDENT (session-based auth)
# ============================================================
class Student(db.Model):
    __tablename__ = 'student'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(80), unique=True, nullable=False, index=True)
    # Stores a werkzeug password hash — NOT plaintext
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    gender = db.Column(db.String(20), default='')
    dob = db.Column(db.String(20), default='')
    phone = db.Column(db.String(40), default='')
    email = db.Column(db.String(200), default='')
    course = db.Column(db.String(120), default='')
    year_group = db.Column(db.String(10), default='', index=True)
    level = db.Column(db.String(10), default='')
    profile_pic = db.Column(db.String(500), default=None)
    status = db.Column(db.String(20), default='Active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def year_status(self):
        """Return the status of this student's year group: 'Active', 'Completed', or 'Unknown'."""
        if not self.year_group:
            return 'Unknown'
        yg = YearGroup.query.filter_by(year=str(self.year_group)).first()
        return yg.status if yg else 'Unknown'


# ============================================================
# YEAR GROUP (gates signup + voting rights)
# ============================================================
class YearGroup(db.Model):
    __tablename__ = 'year_group'
    id = db.Column(db.Integer, primary_key=True)
    year = db.Column(db.String(10), unique=True, nullable=False, index=True)
    code = db.Column(db.String(40), nullable=False)
    status = db.Column(db.String(20), default='Active')  # 'Active' or 'Completed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================================
# EVENTS / NEWS
# ============================================================
class Event(db.Model):
    __tablename__ = 'event'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default='')
    location = db.Column(db.String(200), default='')
    event_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class News(db.Model):
    __tablename__ = 'news'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, default='')
    image = db.Column(db.String(500), default=None)
    posted_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# ============================================================
# CONTACT MESSAGES
# ============================================================
class ContactMessage(db.Model):
    __tablename__ = 'contact_message'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(200), default='')
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============================================================
# CONTRIBUTIONS / PAYMENTS
# ============================================================
class Contribution(db.Model):
    __tablename__ = 'contribution'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default='')
    amount = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    payments = db.relationship('Payment', backref='contribution', lazy=True,
                               cascade='all, delete-orphan')


class Payment(db.Model):
    __tablename__ = 'payment'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contribution_id = db.Column(db.Integer, db.ForeignKey('contribution.id'), nullable=False)
    amount = db.Column(db.Float, default=0.0)
    method = db.Column(db.String(60), default='Mobile Money')
    reference = db.Column(db.String(120), default='')
    note = db.Column(db.Text, default='')
    status = db.Column(db.String(20), default='pending')  # pending | confirmed | rejected
    receipt_no = db.Column(db.String(40), unique=True, nullable=False)
    paid_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    @staticmethod
    def generate_receipt():
        return f"GNMTC-{datetime.utcnow().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"


# ============================================================
# HOME PAGE CARDS
# ============================================================
class HomeCard(db.Model):
    __tablename__ = 'home_card'
    id = db.Column(db.Integer, primary_key=True)
    eyebrow = db.Column(db.String(80), default='')
    title = db.Column(db.String(200), default='')
    description = db.Column(db.Text, default='')
    image = db.Column(db.String(500), default=None)
    order = db.Column(db.Integer, default=0, index=True)


# ============================================================
# ABOUT PAGE PEOPLE
# ============================================================
class AboutPerson(db.Model):
    __tablename__ = 'about_person'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(200), default='')
    note = db.Column(db.Text, default='')
    icon = db.Column(db.String(20), default='🎓')
    order = db.Column(db.Integer, default=0, index=True)


# ============================================================
# GUEST PAGE — ADMINISTRATION + GALLERY
# ============================================================
class GuestAdmin(db.Model):
    __tablename__ = 'guest_admin'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(120), default='')
    photo = db.Column(db.String(500), default=None)
    order = db.Column(db.Integer, default=0, index=True)


class GalleryImage(db.Model):
    __tablename__ = 'gallery_image'
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String(500), nullable=False)
    caption = db.Column(db.String(300), default='')
    order = db.Column(db.Integer, default=0, index=True)


# ============================================================
# ANNOUNCEMENTS
# ============================================================
class Announcement(db.Model):
    __tablename__ = 'announcement'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(80), default='General')
    file = db.Column(db.String(500), default=None)
    file_name = db.Column(db.String(255), default=None)
    is_pinned = db.Column(db.Boolean, default=False, index=True)
    published_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# ============================================================
# POLLS
# ============================================================
class Poll(db.Model):
    __tablename__ = 'poll'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, default='')
    is_active = db.Column(db.Boolean, default=True, index=True)
    order = db.Column(db.Integer, default=0, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    options = db.relationship('PollOption', backref='poll', lazy=True,
                              cascade='all, delete-orphan',
                              order_by='PollOption.order')


class PollOption(db.Model):
    __tablename__ = 'poll_option'
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    image = db.Column(db.String(500), default=None)
    order = db.Column(db.Integer, default=0, index=True)

    votes = db.relationship('PollVote', backref='option', lazy=True,
                            cascade='all, delete-orphan')


class PollVote(db.Model):
    __tablename__ = 'poll_vote'
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False, index=True)
    option_id = db.Column(db.Integer, db.ForeignKey('poll_option.id'), nullable=False, index=True)
    # Stores "student_<id>" (or legacy UUID for old rows)
    voter_id = db.Column(db.String(80), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('poll_id', 'voter_id', name='uq_poll_voter'),
    )


# ============================================================
# SRC EXECUTIVES / PAST LEADERS
# ============================================================
class SRCExecutive(db.Model):
    __tablename__ = 'src_executive'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    position = db.Column(db.String(120), default='')
    photo = db.Column(db.String(500), default=None)
    order = db.Column(db.Integer, default=0, index=True)


class PastLeader(db.Model):
    __tablename__ = 'past_leader'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(60), default='President')  # President | Principal
    years = db.Column(db.String(60), default='')
    photo = db.Column(db.String(500), default=None)
    order = db.Column(db.Integer, default=0, index=True)


# ============================================================
# REQUESTS / COMPLAINTS
# ============================================================
class PollRequest(db.Model):
    __tablename__ = 'poll_request'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=True)
    student_name = db.Column(db.String(200), default='')
    student_reg = db.Column(db.String(80), default='')
    student_phone = db.Column(db.String(40), default='')
    student_email = db.Column(db.String(200), default='')
    suggestion = db.Column(db.Text, default='')
    status = db.Column(db.String(20), default='pending', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    student = db.relationship('Student', backref='poll_requests')


class SignupRequest(db.Model):
    __tablename__ = 'signup_request'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), default='')
    gender = db.Column(db.String(20), default='')
    student_id = db.Column(db.String(80), default='')
    phone = db.Column(db.String(40), default='')
    course = db.Column(db.String(120), default='')
    dob = db.Column(db.String(20), default='')
    year_group = db.Column(db.String(10), default='')
    level = db.Column(db.String(10), default='')
    message = db.Column(db.Text, default='')
    status = db.Column(db.String(20), default='pending', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class RecoveryRequest(db.Model):
    __tablename__ = 'recovery_request'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), default='')
    student_id = db.Column(db.String(80), default='')
    phone = db.Column(db.String(40), default='')
    year_group = db.Column(db.String(10), default='')
    message = db.Column(db.Text, default='')
    status = db.Column(db.String(20), default='pending', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class Complaint(db.Model):
    __tablename__ = 'complaint'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=True)
    student_name = db.Column(db.String(200), default='')
    student_reg = db.Column(db.String(80), default='')
    student_phone = db.Column(db.String(40), default='')
    subject = db.Column(db.String(200), default='')
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    student = db.relationship('Student', backref='complaints')
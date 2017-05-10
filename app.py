from flask import Flask, render_template, redirect, url_for, flash, session, g, get_flashed_messages
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, ValidationError
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

__dbfn__ = "DVTCinventory"
__sqlext__ = '.sqlite'
__sql_inventory_fn__ = os.getcwd() + os.sep + __dbfn__ + __sqlext__

# for when windows thinks the home directory is somewhere inconvenient
__sql_inventory_fn__ = "C:\\Users\\2053_HSUF\\PycharmProjects\\phonehome\\DVTCinventory.sqlite"

print("Database file located at: {}".format(__sql_inventory_fn__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + __sql_inventory_fn__
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = "people"
    id = db.Column(db.Integer, primary_key=True)
    badge = db.Column(db.String(80), unique=True)
    username = db.Column(db.String(40), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    phone_number = db.Column(db.String(12))
    admin = db.Column(db.Boolean)

# fake_user = User(badge='12345', username='joesuber', email='', password='12345',
#                phone_number='913-203-5347', admin=True)


class Phone(UserMixin, db.Model):
    """  will add relations to User http://flask-sqlalchemy.pocoo.org/2.1/quickstart/"""
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    MEID = db.Column(db.String(28), unique=True)
    SKU = db.Column(db.String(50))
    MODEL = db.Column(db.String(50))
    Hardware_Type = db.Column(db.String(50))
    Hardware_Version = db.Column(db.String(50))
    In_Date = db.Column(db.String(50))
    Archived = db.Column(db.String(50))
    TesterName = db.Column(db.String(80))
    DVT_Admin = db.Column(db.String(80))
    MSLPC = db.Column(db.String(50))
    Comment = db.Column(db.String(255))

db.create_all()

class Unique(object):
    """ validator for FlaskForm that demands field uniqueness against the current database entries """
    def __init__(self, model, field, message=None):
        self.model = model
        self.field = field
        if not message:
            message = u'already exists!'
        self.message = message

    def __call__(self, form, field):
        check = self.model.query.filter(self.field == field.data).first()
        if check:
            raise ValidationError(self.message)


class Exists(object):
    """ validator for FlaskForm that demands that an item exists """
    def __init__(self, model, field, message=None):
        self.model = model
        self.field = field
        if not message:
            message = u'does not exist in database!'
        self.message = message

    def __call__(self, form, field):
        check = self.model.query.filter(self.field == field.data).first()
        if not check:
            raise ValidationError(self.message)


class LoginForm(FlaskForm):
    badge = StringField('badge', validators=[InputRequired(), Length(min=4, max=80),
                                             Exists(User, User.badge,
                                                    message="Badge does not belong to a registered user")])


class MeidForm(FlaskForm):
    meid = StringField('MEID', validators=[InputRequired(),
                                           Exists(Phone, Phone.MEID,
                                                  message="MEID does not match any devices in database")])


class RegisterForm(FlaskForm):
    __tablename__ = "devices"
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(min=4, max=50),
                                             Unique(User, User.email, message="Email address already in use")])
    badge = StringField('badge', validators=[InputRequired(), Length(min=4, max=80),
                                             Unique(User, User.badge, message="Badge number already assigned!")])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15),
                                                   Unique(User, User.username, message="Please choose another name")])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    phone_number = StringField('phone number', validators=[Length(min=4, max=12)])
    admin = BooleanField('admin')


class NewDevice(FlaskForm):
    MEID = StringField('MEID', validators=[InputRequired(), Length(min=10, max=24),
                                           Unique(Phone, Phone.MEID, message="This MEID is already in the database")])
    SKU =  StringField('SKU', validators=[InputRequired(), Length(min=4, max=80)])
    MODEL =  StringField('MODEL', validators=[InputRequired(), Length(min=4, max=80)])
    Hardware_Version = StringField('Hardware_Version', validators=[InputRequired(), Length(min=4, max=80)])
    Hardware_Type =  StringField('Hardware_Type', validators=[InputRequired(), Length(min=4, max=80)])
    MSLPC =  StringField('MSLPC', validators=[InputRequired(), Length(min=4, max=80)])
    Comment =  StringField('Comment', validators=[InputRequired(), Length(min=4, max=80)])


def change_ownership(device, username):
    device.TesterName = username
    print("{}, {} is now owned by {}".format(device.MODEL, device.MEID, session['user']))
    db.session.commit()
    return 1


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#step 1, get the badge to get the user
@app.route('/', methods=['GET', 'POST'])
def index():
    session['user'] = None
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(badge=form.badge.data).first()
        session['user'] = user.username
        return redirect(url_for('meid'))
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    return render_template('index.html', form=form)

# step 2, get the device
@app.route('/meid', methods=['GET', 'POST'])
def meid():
    form = MeidForm()
    if form.validate_on_submit():
        device = Phone.query.filter_by(MEID=form.meid.data).first()
        if device:
            change_ownership(device, session['user'])
            flash("{}, {} is now owned by {}".format(device.MODEL, device.MEID, session['user']))

        return redirect(url_for('index'))

    return render_template('meid.html', form=form)


@app.route('/newperson', methods=['GET', 'POST'])
def newperson():
    form = RegisterForm()
    if app.config['newid']:
        form.badge.data = app.config['newid']

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        logged = User(badge=form.badge.data,
                      email=form.email.data,
                      username = form.username.data,
                      password = hashed_password,
                      admin = form.admin.data)
        db.session.add(logged)
        db.session.commit()
        if app.config['meid'] == None:          # no device presented yet
            return redirect(url_for('meid'))
        else:
            return redirect(url_for('target_badge'))    # have user & device, go get target

    return render_template('signup.html', form=form)


@app.route('/newdevice', methods=['GET', 'POST'])
def newdevice():
    form = NewDevice()

    if app.config['new_meid']:
        form.MEID.data = app.config['new_meid']
        app.config['new_meid'] = None
    if form.validate_on_submit():
        new_device = Phone(MEID = form.MEID.data,
                           OEM = form.OEM.data,
                           SKU = form.SKU.data,
                           IMEI = form.IMEI.data,
                           MODEL = form.MODEL.data,
                           Hardware_Type = form.Hardware_Type.data,
                           In_Date = form.In_Date.data,
                           Out_Date = form.Out_Date.data,
                           Archived = form.Archived.data,
                           TesterName = form.TesterName.data,
                           DVT_Admin = form.DVT_Admin.data,
                           Serial_Number = form.Serial_Number.data,
                           MSLPC = form.MSLPC.data,
                           Comment = form.Comment.data)
        db.session.add(new_device)
        db.session.commit()
        app.config['meid'] = newdevice
        return redirect(url_for('target_badge'))
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('newdevice.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/admin_login')
@login_required
def admin_login():
    session['admin'] = login_user()
    return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
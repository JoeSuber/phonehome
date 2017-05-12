from flask import Flask, render_template, redirect, url_for, flash, session, g, get_flashed_messages
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, ValidationError
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pickle, time, os

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

###########################
#### Database Tables ######
###########################
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


class Phone(db.Model):
    """  will add relations to User ...http://flask-sqlalchemy.pocoo.org/2.1/quickstart/"""
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    MEID = db.Column(db.String(28), unique=True)
    SKU = db.Column(db.String(50))
    MODEL = db.Column(db.String(50))
    Hardware_Type = db.Column(db.String(50))
    Hardware_Version = db.Column(db.String(50))
    In_Date = db.Column(db.DateTime(50))
    Archived = db.Column(db.String(50))
    TesterId = db.Column(db.Integer)
    DVT_Admin = db.Column(db.String(80))
    MSLPC = db.Column(db.String(50))
    History = db.Column(db.LargeBinary)
    Comment = db.Column(db.String(255))

db.create_all()

##########################
##### Validators #########
##########################
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Unique(object):
    """ validator for FlaskForm that demands field uniqueness against the current database entries """
    def __init__(self, model, field, message=None):
        self.model = model
        self.field = field
        if not message:
            message = u'not validated'
        self.message = message

    def __call__(self, form, field):
        check = self.model.query.filter(self.field == field.data).first()
        if check:
            raise ValidationError(self.message)


class Exists(Unique):
    """ validator for FlaskForm that demands that an item exists """
    def __call__(self, form, field):
        check = self.model.query.filter(self.field == field.data).first()
        if not check:
            raise ValidationError(self.message)


##########################
######## Forms ###########
##########################
class BadgeEntryForm(FlaskForm):
    badge = StringField('badge', validators=[InputRequired(),
                                             Length(min=4, max=40),
                                             Exists(User, User.badge,
                                                    message="Badge does not belong to a registered user")])


class MeidForm(FlaskForm):
    meid = StringField('MEID', validators=[InputRequired(),
                                           Exists(Phone, Phone.MEID,
                                                  message="MEID does not match any devices in database")])


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(),
                                                   Exists(User, User.username, message="Not a registered username")])
    password = PasswordField('password', validators=[InputRequired(),
                                                     Length(min=8, max=80)])


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(min=4, max=50),
                                             Unique(User, User.email, message="Email address already in use")])
    badge = StringField('badge', validators=[InputRequired(), Length(min=4, max=80),
                                             Unique(User, User.badge, message="Badge number already assigned!")])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15),
                                                   Unique(User, User.username, message="Please choose another name")])
    password = PasswordField('password', validators=[InputRequired(),
                                                     Length(min=8, max=80, message="Passwords are 8-80 characters")])
    phone_number = StringField('phone xxx-xxx-xxxx', validators=[Length(min=4, max=12)])
    admin = BooleanField('admin')


class NewDevice(FlaskForm):
    MEID = StringField('MEID', validators=[InputRequired(), Length(min=10, max=24),
                                           Unique(Phone, Phone.MEID, message="This MEID is already in the database")])
    SKU =  StringField('SKU', validators=[InputRequired(), Length(min=2, max=80)])
    MODEL =  StringField('MODEL', validators=[InputRequired(), Length(min=2, max=80)])
    Hardware_Version = StringField('Hardware_Version', validators=[Length(min=1, max=40)])
    Hardware_Type =  StringField('Hardware_Type', validators=[Length(min=1, max=40)])
    MSLPC =  StringField('MSLPC', validators=[InputRequired(), Length(min=2, max=40)])
    Comment =  StringField('Comment', validators=[Length(min=2, max=80)])

###########################
####### Routes ############
###########################

# step 1, get the badge to get the user
@app.route('/', methods=['GET', 'POST'])
def index():
    session['userid'] = None
    form = BadgeEntryForm()
    if form.validate_on_submit():
        user = User.query.filter_by(badge=form.badge.data).first()
        session['userid'] = user.id
        return redirect(url_for('meid'))
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    return render_template('index.html', form=form)


# step 2, get the device, change owner
@app.route('/meid', methods=['GET', 'POST'])
def meid():
    flash("session user = {}".format(session['userid']))
    form = MeidForm()
    if form.validate_on_submit():
        device = Phone.query.filter_by(MEID=form.meid.data).first()
        if device and session['userid']:
            ### change owner of device and append new owner to history blob ####
            device.TesterId = session['userid']
            device.History = pickle.dumps(pickle.loads(device.History).append((session['userid'], time.time())))
            db.session.commit()
            flash("userid: {} took device: {}".format(session['userid'], device.MEID))
            session['userid'], device = None, None
        return redirect(url_for('index'))

    return render_template('meid.html', form=form)

"""todo: make page that takes MEID and shows history of device"""

@app.route('/newperson', methods=['GET', 'POST'])
# @login_required
def newperson():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        print(form.password.data)
        logged = User(badge=form.badge.data,
                      email=form.email.data,
                      username = form.username.data,
                      password = hashed_password,
                      phone_number = form.phone_number.data,
                      admin = form.admin.data)
        db.session.add(logged)
        db.session.commit()
        print("NEW USER!  {}".format(logged.username))
        flash("created new user: {}".format(logged.username))

    return render_template('signup.html', form=form)


@app.route('/newdevice', methods=['GET', 'POST'])
@login_required
def newdevice():
    form = NewDevice()
    if form.validate_on_submit():
        new_device = Phone(MEID = form.MEID.data,
                           SKU = form.SKU.data,
                           MODEL = form.MODEL.data,
                           Hardware_Type = form.Hardware_Type.data,
                           Hardware_Version=form.Hardware_Version.data,
                           MSLPC = form.MSLPC.data,
                           History = pickle.dumps(list()),
                           Comment = form.Comment.data)
        db.session.add(new_device)
        db.session.commit()
        return redirect(url_for('newdevice'))
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('newdevice.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print(form.username.data)
        user = User.query.filter_by(username=form.username.data).first()
        print("user pw: {}".format(user.password))
        print("form pw: {}".format(form.password.data))

        if check_password_hash(user.password, form.password.data):
            print("LOGGED IN! {}".format(user.email))
            login_user(user)
        redirect(url_for('currentuser'))
    return render_template('login.html', form=form)


@app.route('/currentuser')
@login_required
def currentuser():
    return "<h1> Current user is {} </h1>".format(current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':

    app.run(debug=True)
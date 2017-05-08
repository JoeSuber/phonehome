from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, ValidationError
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Iamtheverymodelofamodernmajorgeneral'

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
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Phone(UserMixin, db.Model):
    """  will add relations to User http://flask-sqlalchemy.pocoo.org/2.1/quickstart/"""
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    MEID = db.Column(db.String(28), unique=True)
    OEM = db.Column(db.String(50))
    SKU = db.Column(db.String(50))
    IMEI = db.Column(db.String(50))
    MODEL = db.Column(db.String(50))
    Hardware_Type = db.Column(db.String(50))
    In_Date = db.Column(db.String(50))
    Out_Date = db.Column(db.String(50))
    Archived = db.Column(db.String(50))
    TesterName = db.Column(db.String(80))
    DVT_Admin = db.Column(db.String(80))
    Serial_Number = db.Column(db.String(50))
    MSLPC = db.Column(db.String(50))
    Comment = db.Column(db.String(255))

db.create_all()

class Unique(object):
    """ validator for FlaskForm that checks field uniqueness against the current database entries """
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


class LoginForm(FlaskForm):
    badge = StringField('badge', validators=[InputRequired(), Length(min=4, max=80)])

class MeidForm(FlaskForm):
    meid = StringField('MEID', validators=[InputRequired()])

class TargetBadgeForm(FlaskForm):
    target_badge = StringField('Badge Target', validators=[InputRequired()])

class RegisterForm(FlaskForm):
    __tablename__ = "devices"
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50),
                                             Unique(User, User.email, message="Email address already in use")])
    badge = StringField('badge', validators=[InputRequired(), Length(min=4, max=80),
                                             Unique(User, User.badge, message="Badge number already assigned!")])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15),
                                                   Unique(User, User.username, message="Please choose another name")])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    admin = BooleanField('admin')

class NewDevice(FlaskForm):
    MEID = StringField('MEID', validators=[InputRequired(), Length(min=4, max=80),
                                           Unique(Phone, Phone.MEID, message="This MEID is already in the database")])
    OEM =  StringField('OEM', validators=[InputRequired(), Length(min=4, max=80)])
    SKU =  StringField('SKU', validators=[InputRequired(), Length(min=4, max=80)])
    IMEI = StringField('IMEI', validators=[InputRequired(), Length(min=4, max=80)])
    MODEL =  StringField('MODEL', validators=[InputRequired(), Length(min=4, max=80)])
    Hardware_Type =  StringField('Hardware_Type', validators=[InputRequired(), Length(min=4, max=80)])
    In_Date =  StringField('In_Date', validators=[InputRequired(), Length(min=4, max=80)])
    Out_Date =  StringField('Out_Date', validators=[InputRequired(), Length(min=4, max=80)])
    Archived =  StringField('Archived', validators=[InputRequired(), Length(min=4, max=80)])
    TesterName =  StringField('TesterName', validators=[InputRequired(), Length(min=4, max=80)])
    DVT_Admin =  StringField('DVT_Admin', validators=[InputRequired(), Length(min=4, max=80)])
    Serial_Number =  StringField('Serial_Number', validators=[InputRequired(), Length(min=4, max=80)])
    MSLPC =  StringField('MSLPC', validators=[InputRequired(), Length(min=4, max=80)])
    Comment =  StringField('Comment', validators=[InputRequired(), Length(min=4, max=80)])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#step 1, get the badge to log in the user
@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    app.config['user'] = None

    if form.validate_on_submit():
        user = User.query.filter_by(badge=form.badge.data).first()
        if user:
            app.config['user'] = user
            print("user = {}".format(app.config['user'].username))
            return redirect(url_for('meid'))

        return redirect(url_for('newperson'))
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    return render_template('index.html', form=form)

# step 2, get the device
@app.route('/meid', methods=['GET', 'POST'])
def meid():
    app.config['meid'] = None
    form = MeidForm()
    if form.validate_on_submit():
        device = Phone.query.filter_by(MEID=form.meid.data).first()
        print("device = {}".format(device))
        if device:
            app.config['meid'] = device
            return redirect(url_for('target_badge'))
        return redirect(url_for('newdevice'))

    return render_template('meid.html', form=form)

# step 3, get the person the current user is targeting, swap device ownership appropriately
@app.route('/target_badge', methods=['GET', 'POST'])
def target_badge():
    form = TargetBadgeForm()
    if form.validate_on_submit():
        target = User.query.filter_by(badge=form.badge.data).first()

        if target:
            device_owner_username = app.config['meid'].TesterName
            if app.config['user'].username == device_owner_username:    # give to target
                app.config['meid'].TesterName = target.username
                db.session.commit()
            elif target.username == device_owner_username:              # take from target
                app.config['meid'].TesterName = app.config['user'].username
                db.session.commit()

            app.config['meid'] = None
            app.config['user'] = None
            return redirect(url_for('/'))       # the task is done, go back to start

        return redirect(url_for('newperson'))   # no target person to trade devices with

    return render_template('target_badge.html', form=form)


@app.route('/newperson', methods=['GET', 'POST'])
def newperson():
    form = RegisterForm(badge=app.config['user'].badge)
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        logged = User(badge=form.badge.data,
                        email=form.email.data,
                        username = form.username.data,
                        password = hashed_password,
                        admin = form.admin.data)
        db.session.add(logged)
        db.session.commit()
        app.config['user'] = logged
        if app.config['meid'] == None:          # no device presented yet
            return redirect(url_for('meid'))
        else:
            return redirect(url_for('target_badge'))    # have user & device, go get target
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'
    return render_template('signup.html', form=form)


@app.route('/newdevice', methods=['GET', 'POST'])
def newdevice():
    form = NewDevice()
    if form.validate_on_submit():
        new_device = NewDevice(MEID = form.MEID.data,
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
                               Serial_Number = form.SKU.data,
                               MSLPC = form.SKU.data,
                               Comment = form.SKU.data)
        db.session.add(new_device)
        db.session.commit()

        return '<h1>New Device Entered!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('newdevice.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
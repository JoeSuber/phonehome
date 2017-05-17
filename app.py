from flask import Flask, render_template, redirect, url_for, flash, session, request, g, get_flashed_messages
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, ValidationError, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pickle, os, csv
from datetime import datetime

# todo: take a look at codepen.io
###################################################################################
# DONT FORGET! to uncomment the '@login_required' for newperson() upon deployment
###################################################################################

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

__dbfn__ = "DVTCinventory"
__sqlext__ = '.sqlite'
__sql_inventory_fn__ = os.getcwd() + os.sep + __dbfn__ + __sqlext__

if os.name is 'nt':
    __sql_inventory_fn__ = "C:\\Users\\2053_HSUF\\PycharmProjects\\phonehome\\DVTCinventory.sqlite"

print("Database file located at: {}".format(__sql_inventory_fn__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + __sql_inventory_fn__
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WERKZEUG_DEBUG_PIN'] = False
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
    badge = db.Column(db.String(40), unique=True)
    username = db.Column(db.String(40), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(94))
    phone_number = db.Column(db.String(12))
    admin = db.Column(db.Boolean)


class Phone(db.Model):
    """  will add relations to User ...http://flask-sqlalchemy.pocoo.org/2.1/quickstart/"""
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    MEID = db.Column(db.String(28), unique=True)
    SKU = db.Column(db.String(50))
    MODEL = db.Column(db.String(50))
    OEM = db.Column(db.String(16))
    Hardware_Type = db.Column(db.String(50))
    Hardware_Version = db.Column(db.String(50))
    In_Date = db.Column(db.DateTime)
    Archived = db.Column(db.String(50))
    TesterId = db.Column(db.Integer)
    DVT_Admin = db.Column(db.String(80))
    MSL = db.Column(db.String(50))
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
    OEM = StringField('OEM', validators=[InputRequired()])
    MEID = StringField('MEID', validators=[InputRequired(), Length(min=10, max=24),
                                           Unique(Phone, Phone.MEID, message="This MEID is already in the database")])
    SKU = StringField('SKU', validators=[InputRequired(), Length(min=2, max=80)])
    MODEL = StringField('MODEL', validators=[InputRequired(), Length(min=2, max=80)])
    Hardware_Version = StringField('Hardware Version', validators=[Length(min=1, max=40)])
    Hardware_Type = StringField('Hardware Type', validators=[Length(min=1, max=40)])
    MSL = StringField('MSL', validators=[InputRequired(), Length(min=2, max=40)])
    Comment = StringField('Comment', validators=[Length(min=2, max=80)])


###########################
####### Routes ############
###########################
@app.route('/', methods=['GET', 'POST'])
def index():
    # step 1, get the badge to get the user
    session['userid'] = None
    form = BadgeEntryForm()
    if form.validate_on_submit():
        user = User.query.filter_by(badge=form.badge.data).first()
        session['userid'] = user.id
        return redirect(url_for('meid'))

    return render_template('index.html', form=form)


@app.route('/meid', methods=['GET', 'POST'])
def meid():
    # step 2, get the device, change owner
    flash("session user = {}".format(session['userid']))
    form = MeidForm()
    if form.validate_on_submit():
        device = Phone.query.filter_by(MEID=form.meid.data).first()
        if device and session['userid']:
            # change owner of device and append new owner to history blob ####
            device.TesterId = session['userid']
            device.In_Date = datetime.utcnow()
            history = pickle.loads(device.History)
            history.append((session['userid'], datetime.utcnow()))
            device.History = pickle.dumps(history)
            db.session.commit()
            flash("userid: {} took device: {}".format(session['userid'], device.MEID))
            session['userid'], device = None, None
        return redirect(url_for('index'))

    return render_template('meid.html', form=form)

"""
    todo: make page that takes MEID and shows history of device
    todo: function for taking device.History list into json (or something)
"""


@app.route('/newperson', methods=['GET', 'POST'])
# @login_required
def newperson():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        logged = User(badge = form.badge.data,
                      email = form.email.data,
                      username = form.username.data,
                      password = hashed_password,
                      phone_number = form.phone_number.data,
                      admin = form.admin.data)
        db.session.add(logged)
        db.session.commit()
        print("NEW USER!  {}".format(logged.username))
        flash("created new user: {}".format(logged.username))
        return redirect(url_for('admin'))

    return render_template('signup.html', form=form)


@app.route('/newdevice', methods=['GET', 'POST'])
@login_required
def newdevice():
    form = NewDevice()
    if form.validate_on_submit():
        new_device = Phone(OEM = form.OEM.data,
                           MEID = form.MEID.data,
                           SKU = form.SKU.data,
                           MODEL = form.MODEL.data,
                           Hardware_Type = form.Hardware_Type.data,
                           Hardware_Version=form.Hardware_Version.data,
                           MSL = form.MSL.data,
                           History = pickle.dumps([(session['userid'], datetime.utcnow())]),
                           Comment = form.Comment.data,
                           In_Date = datetime.utcnow(),
                           DVT_Admin = current_user.id)

        db.session.add(new_device)
        db.session.commit()
        return redirect(url_for('newdevice'))

    return render_template('newdevice.html', form=form)


@app.route('/admin')
@login_required
def admin():
    user = User.query.get(int(current_user.id))
    print("{} user admin: {}".format(user.username, user.admin))
    if user.admin:
        return render_template('admin.html')
    print("NOT an admin: {}".format(user.username))
    flash("NOT an admin: {}".format(user.username))
    return redirect(url_for('login'))


@app.route('/meidedit', methods=['GET', 'POST'])
@login_required
def meidedit():
    form = MeidForm()
    user = User.query.get(int(current_user.id))
    print("user.admin = {}".format(user.admin))
    if form.validate_on_submit() and user.admin:
        print("checking MEID {}".format(form.meid.data))
        session['editingMEID'] = form.meid.data
        return redirect(url_for('editdevice'))
    return render_template('meidedit.html', form=form)


@app.route('/editdevice', methods=['GET', 'POST'])
@login_required
def editdevice():
    try:
        device = Phone.query.filter_by(MEID=session['editingMEID']).first()
        print("comment: {}".format(device.Comment))
    except KeyError:
        return redirect(url_for('meidedit'))
    # fill is some form blanks for user:
    newform = NewDevice(MEID=device.MEID,
                        SKU=device.SKU,
                        MODEL=device.MODEL,
                        Hardware_Type=device.Hardware_Type,
                        Hardware_Version=device.Hardware_Version,
                        MSL=device.MSL,
                        Comment=device.Comment)
    print("newform.validate_on_submit(): {}".format(newform.validate_on_submit()))
    if request.method == "POST":
        history = pickle.loads(device.History)
        history.append((current_user.id, datetime.utcnow()))
        print(history)
        print("updating device: {}".format(device.MEID))
        device.SKU = newform.SKU.data
        device.MODEL = newform.MODEL.data
        device.Hardware_Type = newform.Hardware_Type.data
        device.Hardware_Version = newform.Hardware_Version.data
        device.MSL = newform.MSL.data
        device.Comment = newform.Comment.data
        device.History = pickle.dumps(history)
        db.session.commit()
        used = session.pop('editingMEID')
        flash(" {} MEID = {} was updated".format(device.SKU, used))
        print(" {} MEID = {} was updated".format(device.SKU, used))
        return render_template('admin.html')
    return render_template('editdevice.html', form=newform)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'GET':
        session['sent_from'] = request.args.get('next')
        print("sent from = {}".format(session['sent_from']))
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if check_password_hash(user.password, form.password.data):
            print("LOGGED IN! {}".format(user.email))
            login_user(user, remember=True)
            session['userid'] = user.id
            sent_from = session['sent_from']
            session['sent_from'] = None
            print("current user id = {}".format(current_user.id))
            print("redirecting to {}".format(sent_from))
            return redirect(sent_from or url_for('index'))

        print("LOGIN FAILED")
        flash("LOGIN FAILED")
    return render_template('login.html', form=form)


@app.route('/currentuser', methods=['GET', 'POST'])
@login_required
def currentuser():
    return "<h1> Current user is {} </h1>".format(current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session['userid'] = None
    return redirect(url_for('index'))

#########################
###### Import Data ######
#########################
_columns = ['MEID', 'OEM', 'MODEL', 'SKU', 'Hardware_Type', 'Hardware_Version',
           'In_Date', 'Archived', 'TesterId', 'DVT_Admin', 'MSL', 'Comment']


def csvimport(filename=None):
    """ assumes users have kept columns in the list order """
    if not filename:
        filename = os.path.join(os.getcwd(), "samsung.csv")
    columns = _columns
    item_count = 0
    with open(filename, newline='') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for line in spamreader:
            row = {label: item for label, item in zip(columns, line)}
            new_device = Phone(OEM=row['OEM'],
                               MEID=row['MEID'],
                               SKU=row['SKU'],
                               MODEL=row['MODEL'],
                               Hardware_Type=row['Hardware_Type'],
                               Hardware_Version=row['Hardware_Version'],
                               MSL=row['MSL'],
                               History=pickle.dumps([(row['DVT_Admin'], datetime.utcnow())]),
                               Comment=row['Comment'],
                               In_Date=row['In_Date'],
                               Archived=row['Archived'],
                               TesterId=row['TesterId'],
                               DVT_Admin=row['DVT_Admin'])
            item_count += 1
            db.session.add(new_device)
        db.session.commit()
    print("imported {} items".format(item_count))


def csvexport(outfile=None):
    """ create a spreadsheet template for users using the _column list """
    if not outfile:
        outfile = os.path.join(os.getcwd(), "newsheet.csv")
    with open(outfile, 'w', newline='') as output:
        spamwriter = csv.writer(output, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow(_columns)


if __name__ == '__main__':
    app.run(debug=True)
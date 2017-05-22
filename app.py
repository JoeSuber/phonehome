from flask import Flask, render_template, redirect, url_for, flash, session, request, get_flashed_messages
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, BooleanField, ValidationError, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pickle, os, csv
from datetime import datetime, timedelta

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
app.config['MAIL_SERVER'] = 'localhost'
"""
MAIL_PORT : default 25
MAIL_USE_TLS : default False
MAIL_USE_SSL : default False
MAIL_DEBUG : default app.debug
MAIL_USERNAME : default None
MAIL_PASSWORD : default None
MAIL_DEFAULT_SENDER : default None
MAIL_MAX_EMAILS : default None
MAIL_SUPPRESS_SEND : default app.testing
MAIL_ASCII_ATTACHMENTS : default False
"""
DEFAULT_SENDER = 'joe.suber@DVT&C.com'

Bootstrap(app)
mail = Mail(app)
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
    Serial_Number = db.Column(db.String(50))
    Hardware_Version = db.Column(db.String(50))
    In_Date = db.Column(db.DateTime)
    Archived = db.Column(db.Boolean)
    TesterId = db.Column(db.Integer)
    DVT_Admin = db.Column(db.String(80))
    MSL = db.Column(db.String(50))
    History = db.Column(db.LargeBinary)
    Comment = db.Column(db.String(255))

db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##########################
##### Validators #########
##########################
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
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(min=4, max=50),
                                             Unique(User, User.email, message="Email address already in use")])
    badge = StringField('badge', validators=[InputRequired(), Length(min=4, max=80),
                                             Unique(User, User.badge, message="Badge number already assigned!")])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15),
                                                   Unique(User, User.username, message="Please choose another name")])
    password = PasswordField('password', validators=[InputRequired(),
                                                     Length(min=8, max=80, message="Passwords are 8-80 characters")])
    phone_number = StringField('phone xxx-xxx-xxxx', validators=[InputRequired(), Length(min=4, max=12)])
    admin = BooleanField('admin ')


class NewDevice(FlaskForm):
    OEM = StringField('OEM', validators=[InputRequired()])
    MEID = StringField('MEID', validators=[InputRequired(), Length(min=10, max=24),
                                           Unique(Phone, Phone.MEID, message="This MEID is already in the database")])
    SKU = StringField('SKU', validators=[InputRequired(), Length(min=2, max=80)])
    MODEL = StringField('MODEL', validators=[InputRequired(), Length(min=2, max=80)])
    Hardware_Version = StringField('Hardware Version', validators=[InputRequired(), Length(min=1, max=40)])
    Serial_Number = StringField('Serial Number', validators=[InputRequired(), Length(min=6, max=16)])
    Archived = BooleanField('Archived ')
    MSL = StringField('MSL', validators=[InputRequired()])
    Comment = StringField('Comment')


class ChangePassword(FlaskForm):
    account = StringField('user name for which we will change the password: ', validators=[InputRequired(),
                                                   Exists(User, User.username, message="Not a registered username")])
    password = PasswordField('new password:', validators=[InputRequired(), Length(min=8, max=80)])
    retype = PasswordField('re-type   :', validators=[InputRequired(), Length(min=8, max=80)])

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
    try:
        print("a", session['message'])
        flash("{}".format(session['message']))
    except KeyError:
        print("no message")
        pass
    return render_template('index.html', form=form)


@app.route('/meid', methods=['GET', 'POST'])
def meid():
    # step 2, get the device, change owner
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
            session['message'] = "{} now has {}".format(load_user(session['userid']).username, device.MEID)
            session['userid'], device = None, None
        return redirect(url_for('index'))
    username = load_user(session['userid']).username
    flash("session user = {}".format(username))
    return render_template('meid.html', form=form, name=username)

"""
    todo: make page that takes MEID and shows history of device
    todo: function for taking device.History list into json (or something)
"""


@app.route('/newperson', methods=['GET', 'POST'])
# @login_required  ### <-- uncomment after adding first admin user to database
def newperson():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        logged = User(badge=form.badge.data,
                      email=form.email.data,
                      username=form.username.data,
                      password=hashed_password,
                      phone_number=form.phone_number.data,
                      admin=form.admin.data)
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
        new_device = Phone(OEM=form.OEM.data,
                           MEID=form.MEID.data,
                           SKU=form.SKU.data,
                           MODEL=form.MODEL.data,
                           Serial_Number=form.Serial_Number.data,
                           Hardware_Version=form.Hardware_Version.data,
                           MSL=form.MSL.data,
                           History=pickle.dumps([(session['userid'], datetime.utcnow())]),
                           Comment=form.Comment.data,
                           Archived=form.Archived.data,
                           In_Date=datetime.utcnow(),
                           DVT_Admin=current_user.id)

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
        return render_template('admin.html', name=user.username)
    print("NOT an admin: {}".format(user.username))
    flash("NOT an admin: {}".format(user.username))
    return redirect(url_for('login'))


@app.route('/newpass', methods=['GET', 'POST'])
@login_required
def newpass():
    message = None
    user = User.query.get(int(current_user.id))
    form = ChangePassword()
    print("form validate: {}  ...   user.admin: {}".format(form.validate_on_submit(), user.admin))
    if form.validate_on_submit() and user.admin:
        changer = User.query.filter_by(username=form.account.data).first()
        # allow any admin to change any non-admin. Only allow admin to change their own.
        print("user.username = {}".format(user.username))
        print("changer.username = {}".format(changer.username))
        if (not changer.admin) or (user.username == changer.username):
            print("{} ?= {}".format(form.password.data, form.retype.data))
            if form.password.data == form.retype.data:
                changer.password = generate_password_hash(form.password.data)
                db.session.commit()
                print("Changed password for: {}".format(changer.username))
                flash("Changed password for: {}".format(changer.username))
                return redirect(url_for('admin'))
            print("Password feilds don't match!")
            message = "Password feilds don't match!"
        else:
            message = "NOT ALLOWED to change another admin's password"

    return render_template('newpass.html', form=form, name=user.username, message=message)


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
    except KeyError:    # protect against false access attempt
        return redirect(url_for('meidedit'))
    # fill is some form blanks for user:
    newform = NewDevice(MEID=device.MEID,
                        SKU=device.SKU,
                        OEM=device.OEM,
                        MODEL=device.MODEL,
                        Serial_Number=device.Serial_Number,
                        Hardware_Version=device.Hardware_Version,
                        MSL=device.MSL,
                        Archived=device.Archived,
                        Comment=device.Comment)
    print("newform.validate_on_submit(): {}".format(newform.validate_on_submit()))
    if request.method == "POST":
        history = pickle.loads(device.History)
        history.append((current_user.id, datetime.utcnow()))
        print(history)
        print("updating device: {}".format(device.MEID))
        device.SKU = newform.SKU.data
        device.OEM = newform.OEM.data
        device.MODEL = newform.MODEL.data
        device.Serial_Number = newform.Serial_Number.data
        device.Hardware_Version = newform.Hardware_Version.data
        device.MSL = newform.MSL.data
        device.Archived = newform.Archived.data
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
    message = None
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

        message = "Incorrect Password"
    return render_template('login.html', form=form, message=message)


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

################################
###### Import/Export Data ######
################################
_columns = ['MEID', 'OEM', 'MODEL', 'SKU', 'Serial_Number', 'Hardware_Version',
           'In_Date', 'Archived', 'TesterId', 'DVT_Admin', 'MSL', 'Comment']


def csvexport(outfile=None):
    """ create a spreadsheet template for users to fill using the _column list """
    if not outfile:
        outfile = os.path.join(os.getcwd(), "your_own_devices.csv")
    with open(outfile, 'w', newline='') as output:
        spamwriter = csv.writer(output, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow(_columns)
    print("spreadsheet columns exported to: {}".format(outfile))


def datefix(datestr):
    fix = datestr.replace('-','/')
    return datetime.strptime(fix, "%m/%d/%y")


def csvimport(filename=None):
    """ Assumes users have kept columns in the list-order. 
        Puts csv spreadsheet-derived data into database."""
    if not filename:
        filename = os.path.join(os.getcwd(), "samsung.csv")
    columns = _columns
    item_count = 0
    with open(filename, newline='') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for line in spamreader:
            if not item_count:
                item_count = 1
                continue
            row = {label: item for label, item in zip(columns, line)}
            datefixed = ''
            if row['In_Date']:
                try:
                    datefixed = datefix(row['In_Date'])
                except:
                    datefixed = ''
            new_device = Phone(OEM=row['OEM'],
                               MEID=row['MEID'],
                               SKU=row['SKU'],
                               MODEL=row['MODEL'],
                               Serial_Number=row['Serial_Number'],
                               Hardware_Version=row['Hardware_Version'],
                               MSL=row['MSL'],
                               History=pickle.dumps([(row['DVT_Admin'], datetime.utcnow())]),
                               Comment=row['Comment'],
                               In_Date=datefixed,
                               Archived=bool(row['Archived']),
                               TesterId=row['TesterId'],
                               DVT_Admin=row['DVT_Admin'])
            try:
                db.session.add(new_device)
                item_count += 1
            except Exception as e:
                print("ER: {}, {}".format(e, new_device))

        db.session.commit()
    print("imported {} items".format(item_count))


def overdue_report(manager_id, days=14, outfile=None):
    """ query by manager to find devices that need checking-up on
        write a report that can be sent as an attachment to managers. return filename. """
    columns = _columns
    if outfile is None:
        outfile = os.path.join(os.getcwd(), "overdue_report.csv")
    manager = User.query.get(manager_id)
    try:
        assert manager.Admin
    except AssertionError:
        responce = "User: {} is not an Administrator".format(manager.username)
        print(responce)
        return responce
    managers_stuff = Phone.query.filter_by(DVT_Admin=manager.id).all()
    today = datetime.utcnow()
    delta = timedelta(days)
    overdue_stuff = [phone for phone in managers_stuff if (today - phone.In_Date) > delta]

    with open(outfile, 'w', newline='') as output_obj:
        spamwriter = csv.writer(output_obj, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow(columns) # column labels
        for i in overdue_stuff:
            line = [i.MEID, i.OEM, i.MODEL, i.SKU, i.Serial_Number, i.Hardware_Version, str(i.In_Date.date()),
                    i.Archived, load_user(i.TesterId).username, load_user(i.DVT_Admin).username, i.MSL, i.Comment]
            spamwriter.writerow(line)
    print("report file written to = {}".format(outfile))
    return manager.email, outfile


def oem_report(manager_id, oem=None, outfile=None):
    """ prepare a report that lists a manager's devices filtered by OEM """
    columns = _columns
    manager = User.query.get(manager_id)
    if outfile is None:
        outfile = os.path.join(os.getcwd(), "oem_report.csv")
    if oem is None:
        results = Phone.query.filter_by(DVT_Admin=manager_id).all()
    else:
        results = Phone.query.filter_by(DVT_Admin=manager_id).filter_by(OEM=oem).all()

    with open(outfile, 'w', newline='') as output_obj:
        spamwriter = csv.writer(output_obj, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow(columns) # column labels
        for i in results:
            line = [i.MEID, i.OEM, i.MODEL, i.SKU, i.Serial_Number, i.Hardware_Version, str(i.In_Date.date()),
                    i.Archived, load_user(i.TesterId).username, load_user(i.DVT_Admin).username, i.MSL, i.Comment]
            spamwriter.writerow(line)
    print("report file written to = {}".format(outfile))
    return manager.email, outfile


def send_report(email, attachment_fn, sender=None, subject='Overdue Devices Report'):
    if sender is None:
        sender=DEFAULT_SENDER
    message = Message(subject=subject,
                      sender=sender,
                      recipients=[email])
    with app.open_resource(attachment_fn) as attachment:
        message.attach(attachment_fn, "spreadsheet/csv", attachment.read())
    mail.send(message)
    print("sent mail from {} to {}".format(sender, email))


if __name__ == '__main__':
    app.run(debug=True)
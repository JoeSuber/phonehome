from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
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


class Phone(UserMixin, db.Model):
    """  will add relations to User http://flask-sqlalchemy.pocoo.org/2.1/quickstart/"""
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    MEID = db.Column(db.String(28))
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

def unique_badge(form, field):
    return User.query.filter_by(badge=prospect).first()


class LoginForm(FlaskForm):
    badge = StringField('badge', validators=[InputRequired(), Length(min=4, max=80)])


class AdminLoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=40)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    badge = StringField('badge', validators=[InputRequired(), Length(min=4, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    __tablename__ = "devices"
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    badge = StringField('badge', validators=[InputRequired(), Length(min=4, max=80)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    admin = BooleanField('admin')


class NewDevice(FlaskForm):
    MEID = StringField('MEID', validators=[InputRequired(), Length(min=4, max=80)])
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


@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(badge=form.badge.data).first()
        if user:
            return redirect(url_for('dashboard'))

        app.config['MEID'] = form.badge.data
        return redirect(url_for('newperson'))
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    return render_template('index.html', form=form)


@app.route('/newperson', methods=['GET', 'POST'])
def newperson():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        logged = User(badge=form.badge.data,
                        email=form.email.data,
                        username = form.username.data,
                        password = hashed_password,
                        admin = form.admin.data)
        db.session.add(logged)
        db.session.commit()
        return '<h1>New user has been created!</h1>'
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
#references
"""
https://www.geeksforgeeks.org/how-to-use-flask-session-in-python-flask/
https://flask-bcrypt.readthedocs.io/en/1.0.1/
https://github.com/Vuka951/tutorial-code/tree/master/flask-bcrypt
https://www.youtube.com/watch?v=pPSZpCVRbvQ
https://stackoverflow.com/questions/31358578/display-image-stored-as-binary-blob-in-template 
https://flask.palletsprojects.com/en/1.1.x/patterns/fileuploads/
https://github.com/techwithtim/Flask-Web-App-Tutorial
https://github.com/arpanneupane19/Flask-File-Uploads
https://www.youtube.com/watch?v=ZMwrBzyZgto&ab_channel=THESHOW
https://www.youtube.com/watch?v=rQ_sHd2_Ppk&list=PLKbhw6n2iYKieyy9hhLjLMpD9nbOnCVmo&index=8&ab_channel=projectworld
https://github.com/hilalahmad32/user-management-system-in-flask
https://flask.palletsprojects.com/en/2.2.x/patterns/fileuploads/
https://www.youtube.com/watch?time_continue=5&v=8BB3UK_pQy8&feature=emb_logo
https://www.youtube.com/watch?v=3rr3pGX7OsY&t=0s
https://www.youtube.com/watch?v=mS89iL1RHgU&t=0s
https://www.youtube.com/watch?v=OczLouzgJSc&t=0s
https://www.youtube.com/watch?v=v6b4tggM7M0&t=0s
"""


from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask import render_template,flash
from flask import url_for, redirect
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from io import BytesIO
from flask import request, send_file
import sqlite3
from base64 import b64encode
from flask.json import jsonify


ALLOWED_EXTENSIONS_IMAGES = {'png', 'jpg', 'jpeg'}
ALLOWED_EXTENSIONS_TXT = {'txt', 'pdf', 'doc', 'dox'}
ALLOWED_EXTENSIONS_VIDEO = {'mp4', 'avi', 'mkv' ,'mp5'}
ALLOWED_EXTENSIONS_AUDIO = {'mp3', 'aac', 'flac'}

HTTP_404_NOT_FOUND  = 404
HTTP_500_INTERNAL_SERVER_ERROR = 500

app = Flask(__name__)

bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'SXS9376KEY'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#table for user
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

#table admin user
class adminuser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

#table admin key
class adminkey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(20), nullable=False, unique=True)

#table upload files
class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(50))
    data = db.Column(db.LargeBinary)

#table imape upload
class Imageupload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    imagename = db.Column(db.String(50))
    data = db.Column(db.LargeBinary)
    #file_description =db.Column(db.String(80))

#table group
class groupdetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    groupname= db.Column(db.String(50))
    username=db.Column(db.String(50))

#table usergroup
class UserGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    groupname= db.Column(db.String(20))
    UserName=db.Column(db.String(20))

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('user name not unique')

class AdminRegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    admin_key = StringField(validators=[InputRequired(), Length(min=8, max=8)], render_kw={"placeholder": "ADMIN KEY"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('user name not unique')

class AdminKeyForm(FlaskForm):
    admin_key = StringField(validators=[InputRequired(), Length(min=8, max=8)], render_kw={"placeholder": "ADMIN KEY"})
    submit = SubmitField('Generate')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

@app.route('/')
def home():
    return render_template('home.html')

#login page 
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                print("Login Succesfull!!")
                return redirect(url_for('dashboard'))
            else:
                jsonify({'internal server error': 'return back to login page'}), HTTP_500_INTERNAL_SERVER_ERROR
                flash("Wrong Password - Try Again!")
        else:
            flash("That User Doesn't Exist! Try Again...")
    return render_template('login.html', form=form)

#admin login page
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = LoginForm()
    if form.validate_on_submit():
        auser = adminuser.query.filter_by(username=form.username.data).first()
        if auser:
            if bcrypt.check_password_hash(auser.password, form.password.data):
                login_user(auser)
                print("Login Succesfull!!")
                return redirect(url_for('admin_dashboard'))
                
            else:
                jsonify({'internal server error': 'return back to login page'}), HTTP_500_INTERNAL_SERVER_ERROR
                flash("Wrong Password - Try Again!")
        else:
            flash("That User Doesn't Exist! Try Again...")
    return render_template('admin_login.html', form=form)

#register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    print(form)
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

#admin register
@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    form = AdminRegisterForm()
    auser = adminkey.query.filter_by(key=form.admin_key.data).first()
    print(auser,"wetsfd")
    if auser:
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            #add to admin table
            new_user = adminuser(username=form.username.data, password=hashed_password)
            print("hellosss",new_user)
            db.session.add(new_user)
            db.session.commit()
            #add to user table
            new_user = User(username=form.username.data, password=hashed_password)
            print(new_user)
            db.session.add(new_user)
            db.session.commit()
            print('You are now registered and can log in', 'success')
            flash('You are now registered and can log in', 'success')
            return redirect(url_for('admin_login'))
        return render_template('admin_register.html', form=form)
    return render_template('admin_register.html', form=form)

#dashboard page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

#admin dashboard
@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

#admin key generate
@app.route('/admin_key_generate', methods=['GET', 'POST'])
@login_required
def admin_key_generate():
    form = AdminKeyForm()
    print(form)
    if form.validate_on_submit():
        newkey = adminkey(key=form.admin_key.data)
        db.session.add(newkey)
        db.session.commit()
        print('key generated')
        flash('key generated')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_key_generate.html',form=form)

#logout page
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


def file_extension_allowed_files(filename):
    return '.' in filename and \
           (filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_TXT or filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_VIDEO)

#fileupload
@app.route('/fileupload', methods=['POST', 'GET'])
@login_required
def fileupload():
    if request.method == 'POST':
        file = request.files['file']
        if file and file_extension_allowed_files(file.filename):
            upload = Upload(filename=file.filename, data=file.read())
            db.session.add(upload)
            db.session.commit()
            return f'Uploaded: {file.filename}' 
            #return 'file uploaded!', 200
    if request.method == 'GET':
        return render_template('fileupload.html')
    return render_template('fileupload.html')

def file_extension_allowed_image(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_IMAGES

#image upload
@app.route('/imageupload', methods=['POST', 'GET'])
@login_required
def imageupload():
    if request.method == 'POST':
        file = request.files['file']
        if file and file_extension_allowed_image(file.filename):
            upload = Imageupload(imagename=file.filename, data=file.read())
            db.session.add(upload)
            db.session.commit()
            return f'Uploaded: {file.filename}' 
        #return 'file uploaded!', 200
    if request.method == 'GET':
        return render_template('imageupload.html')
    return render_template('imageupload.html')

#download files
@app.route('/download/<upload_id>')
@login_required
def download(upload_id):
    upload = Upload.query.filter_by(id=upload_id).first()
    temp=upload.filename
    print(temp)
    return send_file(BytesIO(upload.data),download_name=temp,as_attachment=True)

#display images page
@app.route('/displayimages/<upload_id>')
@login_required
def displayimages(upload_id):
    upload = Imageupload.query.filter_by(id=upload_id).first()
    image = b64encode(upload.data).decode("utf-8")
    return render_template("displayimages.html", obj=upload, image=image)

@app.route("/display_all_files")
@login_required
def display_all_files():
    files=Upload().query.all()
    return render_template("display_all_files.html",files=files)

@app.route("/display_all_images")
@login_required
def display_all_images():
    files=Imageupload().query.all()
    return render_template("display_all_images.html",files=files)

@app.route("/display_all_group")
@login_required
def display_all_group():
    files=groupdetail().query.all()
    return render_template("display_all_group.html",files=files)

@app.route("/group_images")
@login_required
def group_images():
    return render_template("group_images.html")

@app.route("/group_files")
@login_required
def group_files():
    return render_template("group_files.html")

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.errorhandler(HTTP_404_NOT_FOUND)
def handle_404(e):
    return jsonify({'error':'the page is not found'}), HTTP_404_NOT_FOUND

@app.errorhandler(HTTP_500_INTERNAL_SERVER_ERROR)
def handle_500(e):
    return jsonify({'internal server error': 'return back to login page'}), HTTP_500_INTERNAL_SERVER_ERROR

if __name__ == "__main__":
    app.run(debug=True)

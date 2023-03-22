from flask import Flask, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from datetime import datetime

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo

from flask import request, render_template, flash, redirect, url_for
from flask_login import current_user, login_user, logout_user, login_required

from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin


# instantiate application and database
app = Flask(__name__)


current_year = datetime.now().year
app.config['SECRET_KEY'] = 'this-is-my-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/danielcagney/Library/Mobile Documents/com~apple~CloudDocs/Documents/Developer/flask/myblog/blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# models


class Blogpost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    subtitle = db.Column(db.String(50))
    author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    content = db.Column(db.Text)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)

    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    joined_at = db.Column(db.DateTime(), index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# registration form
class RegistrationForm(FlaskForm):
  username = StringField('Username', validators=[DataRequired()])
  email = StringField('Email', validators=[DataRequired(), Email()])
  password = PasswordField('Password', validators=[DataRequired()])
  password2 = PasswordField('Repeat Password', validators=[
                            DataRequired(), EqualTo('password')])
  submit = SubmitField('Register')

# login form


class LoginForm(FlaskForm):
  email = StringField('Email',
                      validators=[DataRequired(), Email()])
  password = PasswordField('Password', validators=[DataRequired()])
  remember = BooleanField('Remember Me')
  submit = SubmitField('Login')


# create login manager
login_manager = LoginManager()
login_manager.init_app(app)


# user loader
@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))


# registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
  form = RegistrationForm(csrf_enabled=False)
  if form.validate_on_submit():
    # define user with data from form here:
    user = User(username=form.username.data, email=form.email.data)
    # set user's password here:
    user.set_password(form.password.data)
    db.session.add(user)
    db.session.commit()
  return render_template('register.html', title='Register', form=form)


# login route
@app.route('/login', methods=['GET','POST'])
def login():
  error = None
  form = LoginForm()
  if form.validate_on_submit():
    # query User here:
    user = User.query.filter_by(email=form.email.data).first()
    
    if user and user.check_password(form.password.data):
      if True:
      # login user here:
        login_user(user, remember=form.remember.data)
        
        flash('Logged in successfully.')

        
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('index'))
      
    
    else:
      return redirect(url_for('login'))
  return render_template('login.html', form=form, error = error)

@app.route('/logout', methods=['GET','POST'])
def logout():
   logout_user()
   return redirect(url_for('index')) 

# user route
@app.route('/user/<username>')
@login_required
def user(username):
  user = User.query.filter_by(username=username)
  return render_template('user.html', user=user)




@app.route('/')
def index():
    posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).limit(3)
    return render_template('index.html', posts=posts, year=current_year)

@app.route('/landing_page')
def landing_page():
    return render_template('landing_page.html', year=current_year)


@app.route('/about')
def about():
    return render_template('about.html', year=current_year)


@app.route('/post/<int:post_id>')
# @login_required
def post(post_id):
    post = Blogpost.query.filter_by(id=post_id).one()
    # date_posted = post.date_posted.strftime('%B %d, %Y')
    return render_template('post.html', post=post, year=current_year)


@app.route('/contact')
def contact():
    return render_template('contact.html', year=current_year)


@app.route('/add')
@login_required
def add():
    return render_template('add.html', year=current_year)


@app.route('/add', methods=['POST'])
def addpost():
    if request.method == 'POST':
        title = request.form['title']
        subtitle = request.form['subtitle']
        author = request.form['author']
        content = request.form['content']

        post = Blogpost(title=title, subtitle=subtitle, author=author,
                        content=content, date_posted=datetime.now())

        db.session.add(post)
        db.session.commit()

    return redirect(url_for('index'))

@app.route('/older_posts')
def older_posts():
#    older_posts = Blogpost.query.order_by(Blogpost.date_posted.desc()).all()
   older_posts = Blogpost.query.order_by(Blogpost.id.desc()).offset(3)
   return render_template('older_posts.html', posts=older_posts, year=current_year)

if __name__ == "__main__":
    app.run(debug=True)


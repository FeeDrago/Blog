from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from forms import *
from sqlalchemy import ForeignKey
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASH_KEY")

ckeditor = CKEditor(app)
Bootstrap5(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI', 'sqlite:///posts.db')
db = SQLAlchemy()
db.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


def admin_only(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return abort(403)

    return decorated_function


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship('Comment', back_populates='parent_post')


# TODO: Create a User table for all your registered users. 
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, unique=True, nullable=False)
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')


class Comment(db.Model):
    __tablename__ = 'comments'
    text = db.Column(db.String, nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship('User', back_populates='comments')

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship('BlogPost', back_populates='comments')

# sto relationship onoma class pou sundeetai kai se poio attribute summetrika kai stis duo klaseis
# sthn kid class bazw kai ForeginKey tablename.attribute
# sta relationship fields dineis to swsto object otan dhmiourgeis auto to object kai pairnei to attribute back_populates mono tou
# meta mporw px for comment in BLogPost().comments: comment.comment_author_username


with app.app_context():
    db.create_all()

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'GET':
        return render_template("register.html", form=form)
    elif request.method == 'POST' and form.validate_on_submit():
        # Check if there is a user already registered with that email
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if user:
            flash(message='There is already a user registered with that email please try logging in.')
            return redirect(url_for('login'))
        elif not user:  # User with that email does not exist
            new_user = User(username=form.username.data, password=generate_password_hash(password=form.password.data, salt_length=8),email=form.email.data)
            login_user(new_user)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('get_all_posts'))


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'GET':
        return render_template("login.html", form=form)
    elif request.method == 'POST' and form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        # If user does not exist
        if not user:
            flash(message='Sorry there is not a user registered with that email.')
            return redirect(url_for('login'))
        # If user exists and password is correct
        elif user and check_password_hash(pwhash=user.password, password=form.password.data):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        # If user exists but password does not match
        else:
            flash('Invalid password please try again.')
            return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['GET', "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CreateCommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You first need to login to be able to leave a comment.")
            return redirect(url_for("login"))
        # POST and logged in
        else:
            Comment()
            db.session.add(Comment(text=form.body.data,comment_author=current_user, parent_post=db.get_or_404(BlogPost, post_id)))
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
    else:
        return render_template("post.html", post=requested_post, form=form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True)

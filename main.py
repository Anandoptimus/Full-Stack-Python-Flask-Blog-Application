from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
# from sqlalchemy import ForeignKey
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
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

login_manager = LoginManager()
login_manager.init_app(app)
# TODO: Configure Flask-Login


def admin_only(f):
    @wraps(f)
    @login_required
    def decorator_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorator_function



@login_manager.user_loader
def load_user(user_id):
    return User.query.get_or_404(user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user_details.id"))
    author = db.relationship("User", back_populates='post')
    comments = db.relationship("Comment", back_populates="parent_post")



# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = "user_details"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    post = db.relationship("BlogPost", back_populates='author')
    comments = db.relationship("Comment", back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author = db.relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("user_details.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))
    parent_post = db.relationship("BlogPost", back_populates="comments")



with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        word = generate_password_hash(form.password.data, salt_length=8)
        data = User(
            email=form.email.data,
            password=word,
            name=form.name.data
        )
        query = db.session.execute(db.select(User).where(User.email == data.email)).scalar()
        if query:
            flash("You have already signed up using this email, log in instead!")
            return redirect(url_for("login"))
        db.session.add(data)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    print(current_user.is_authenticated)
    form = LoginForm()
    if form.validate_on_submit():
        query = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
        if not query:
            flash("Invalid Email, Try again!")
            return redirect(url_for("login"))
        elif not check_password_hash(query.password, form.password.data):
            flash("Invalid Password, Try again!")
            return redirect(url_for("login"))
        else:
            login_user(query)
            a = login_user(query)
            print(a)
            return redirect(url_for("get_all_posts", id=query.id))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()


    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>" , methods= ["GET", "POST"])
def show_post(post_id):
    # requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    requested_post = BlogPost.query.get_or_404(post_id)
    # comment = db.session.execute(db.select(Comment).order_by(Comment.id)).scalars().all()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to log in or register to comment.")
            return redirect(url_for('login'))
        query_comment = Comment(
            text=form.comment.data,
            author=current_user,
            parent_post=requested_post)

        db.session.add(query_comment)
        db.session.commit()


    # comm = comment.comment.data
        # a = db.session.execute(db.select(Comment).where(Comment.))
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form)


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
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated, g=gravatar)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    # post = db.get_or_404(BlogPost, post_id)
    post = BlogPost.query.get_or_404(post_id)
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
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


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
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True, port=5002)

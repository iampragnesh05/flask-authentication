
from flask import Flask, render_template, request, url_for, redirect, flash, session,send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE DATABASE


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB


class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
        if request.method == 'POST':
            email = request.form['email']
            name = request.form['name']
            password = request.form['password']

            # Hash the password before storing
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

            # Create a new User object and add it to the database
            new_user = User(email=email, name=name, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            session['user_name'] = name

            # Redirect to the secrets page after successful registration
            return redirect(url_for('secrets'))

        return render_template('register.html')


# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Retrieve the user from the database by email
        user = User.query.filter_by(email=email).first()

        if not user:
            # If the user does not exist, flash an error message and redirect back to the login page
            flash('Email not found. Please check your email or register for an account.', 'danger')
            return redirect(url_for('login'))


        if user and check_password_hash(user.password, password):  # Check if password is correct
            # Log the user in
            login_user(user)
            flash('Login successful!', 'success')  # Optional flash message
            return redirect(url_for('secrets'))  # Redirect to the secrets page

        else:
            flash('Invalid credentials. Please try again.', 'danger')  # Flash error message
            return redirect(url_for('login'))  # Redirect back to login page if invalid

    return render_template('login.html')  # Render login form


@app.route('/secrets')
@login_required
def secrets():
    user_name = session.get('user_name')

    return render_template("secrets.html", user_name=user_name)


@app.route('/logout')
@login_required  # Ensure the user is logged in before they can log out
def logout():
    logout_user()  # Logs the user out
    flash('You have been logged out.', 'info')  # Flash a logout message
    return redirect(url_for('login'))  # Redirect the user to the login page after logout


@app.route('/download')
@login_required
def download():
    return send_from_directory('static/files', 'cheat_sheet.pdf', as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)

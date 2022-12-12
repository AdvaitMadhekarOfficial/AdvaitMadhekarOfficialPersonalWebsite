from flask import Blueprint, render_template, redirect, url_for, request, flash
from . import db
from .models import User
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash #To encrypt the password before you put into database.


auth = Blueprint("auth", __name__)

@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user:
          user_account_type = user.account_type
          if(user_account_type == 2):
            if(user.locked_account == False):
              if check_password_hash(user.password, password):
                  flash("Logged in!", category='success')
                  login_user(user, remember=True)
                  return redirect(url_for('views.home'))
              else:
                  flash('Password is incorrect.', category='error')
            else:
              flash("Your account is locked! Please consult a representative to unlock it.", category="error")
          else:
            flash("You are an admin. Please login through the admin portal.", category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html", user=current_user)

@auth.route("/signup", methods=["GET", "POST"])
def signup():
  if request.method == "POST":
      email = request.form.get("email")
      username = request.form.get("username")
      password1 = request.form.get("password1")
      password2 = request.form.get("password2")
      email_exists = User.query.filter_by(email=email).first()
      username_exists = User.query.filter_by(username=username).first()
      
      if email_exists:
          flash('EMAIL IS IN USE!', category='error') # Flashes message on the screen.
      elif username_exists:
          flash('USERNAME IS IN USE!', category='error')
      elif password1 != password2:
          flash('PASSWORDS DON\'T match!', category='error')
      elif len(username) < 2:
          flash('USERNAME IS TOO SHORT!', category='error')
      elif len(password1) < 2:
          flash('PASSWORD IS TOO SHORT!', category='error')
      elif len(email) < 4:
          flash('EMAIL IS INVALID!', category='error')
      else:
        new_user = User(email=email, username=username, password=generate_password_hash(password1, method='sha256'), account_type=2, locked_account = False, money_value = 0)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user, remember=True)
        flash('USER CREATED!!')
        return redirect(url_for('views.home'))
  return render_template("signup.html", user=current_user)

@auth.route("/logout")
@login_required #Can only access this root if you've been loggedin!
def logout():
    logout_user()
    return redirect(url_for("views.home"))
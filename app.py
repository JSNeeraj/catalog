from os import name
from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import backref
from sqlalchemy.orm import relationship 
from werkzeug.utils import redirect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_manager, login_user, logout_user, current_user


app=Flask(__name__)

app.config['SECRET_KEY'] = '7907005697'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db=SQLAlchemy(app)
bcrypt=Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(100), unique=True, nullable=False)
    password=db.Column(db.String(100),nullable=False)
    dir=db.relationship('Dire',backref='creator')


class Dire(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.Integer,db.ForeignKey('user.id'))
    name=db.Column(db.String(300),nullable=False)
    number=db.Column(db.String(300),nullable=False)
    email=db.Column(db.String(300),nullable=False)
    relation=db.Column(db.String(200),nullable=False)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    if not current_user.is_authenticated:
            return redirect('/login')
    else:
        return redirect('/home')


@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect('/home')
        return render_template('login.html')
    else:
        username = request.form.get('username') 
        password = request.form.get('password') 
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect('/home')
        else:
            flash('Wrong credentials')
            return redirect('/login')

@app.route("/home")
def home1():
    if not current_user.is_authenticated:
        return redirect('/login')
    else: 
        dir= Dire.query.filter_by(creator=current_user)
        return render_template('main.html', dir=dir, name=current_user.username )


@app.route("/logout")
def logout():
    logout_user()
    return redirect('/login')


@app.route("/create-dir", methods=['POST'])
def create_dir():
    name=request.form.get('name')
    number=request.form.get('number')
    email=request.form.get('email')
    relation=request.form.get('relation')
    dir=Dire(name=name,creator=current_user,number=number,email=email,relation=relation)
    db.session.add(dir)
    db.session.commit()  
    return redirect('/home')



@app.route("/delete-dir/<int:dir_id>")
def delete_dir(dir_id):
    
    dir=Dire.query.get(dir_id)
    dir.status=True
    db.session.delete(dir)
    db.session.commit()  
    return redirect('/home')




@app.route("/signup")
def signup():
    return render_template('signup.html')


@app.route("/dtbbou")  
def database():
    users=User.query.all()
    return render_template('userdatabase.html', users=users)

@app.route("/create-form", methods=['POST'])
def forms():
    username=request.form.get('username')
    password=request.form.get('password')

    if User.query.filter_by(username=username).first() != None:
            flash('User alredy exists')
            return redirect('/signup')

    new_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user=User(username=username, password=new_password)
    db.session.add(user)
    db.session.commit()
    return redirect('/')


if __name__ == "__main__":
    db.create_all()
    app.run(debug= True)    
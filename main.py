from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, and_

import datetime as dt
import random

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, SelectField, EmailField, TextAreaField
from wtforms.validators import DataRequired, Length, Regexp
from flask_bootstrap import Bootstrap5

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

import csv
import ast
import os
from dotenv import load_dotenv

import send_email
import math


load_dotenv()
FLASK_KEY = os.getenv("FLASK_KEY")
DB_URI = os.getenv("DB_URI")
depth = ast.literal_eval(os.getenv("DEPTH"))
category = ast.literal_eval(os.getenv("CATEGORY"))
stage = ast.literal_eval(os.getenv("STAGE"))
print(depth[0])
# CREATE DB
class Base(DeclarativeBase):
    pass

class DataManager:

    def __init__(self):
        self.app = Flask(__name__)
        # Connect to Database
        self.app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['SECRET_KEY'] = FLASK_KEY
        self.db = SQLAlchemy(self.app, model_class=Base)
        bt = Bootstrap5(self.app)
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        
        # register
        class RegisterForm(FlaskForm):
            username = StringField('Username', validators=[DataRequired()])
            email = EmailField('Email Address', validators=[DataRequired()])
            password = PasswordField('Password', validators=[DataRequired(), 
                                                             Length(min=10, message="Password must be at least 10 characters long."),
                                                             Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$', message="Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character from @$!%*?&.")])
            student = SelectField('Are you a student?', validators=[DataRequired()], choices=[(0, "No"), (1, 'Yes')])
            agreement = SelectField('Do you agree Terms of Use?', validators=[DataRequired()], choices=[(1, 'Agree'), (0, "Disagree")])
            submit = SubmitField('Create New Account', render_kw={'class': 'btn btn-dark'})

        # Login
        class LoginForm(FlaskForm):
            email = EmailField('Email', validators=[DataRequired()])
            password = PasswordField('Password', validators=[DataRequired()])
            submit = SubmitField('Login', render_kw={'class': 'btn btn-dark'})   
        
        # update_information
        class UpdateForm(FlaskForm):
            username = StringField('Username')
            email = EmailField('Email Address')
            student = SelectField('Are you a student?', choices=[(None, '---'), (1, 'Yes'), (0, "No") ])
            submit = SubmitField('Save', render_kw={'class': 'btn btn-dark'})
        
        # Change Password
        class ChangePasswordForm(FlaskForm):
            current_password = PasswordField('Current Password', validators=[DataRequired()])
            new_password = PasswordField('New Password', validators=[DataRequired(),
                                                                    Length(min=10, message="Password must be at least 10 characters long."),
                                                                    Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$', message="Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character.")])
            submit = SubmitField('Save', render_kw={'class': 'btn btn-dark'})

        # Contact Me
        class ContactForm(FlaskForm):
            name = StringField('Name', validators=[DataRequired()])
            email = EmailField('Email Address', validators=[DataRequired()])
            category = SelectField('Category', choices=[("General Inquiries", "General Inquiries"), ("Technical Issues", "Technical Issues"), ("Feature Requests", "Feature Requests"), ("Account Deletion", "Account Deletion"), ("Others", "Others")], validators=[DataRequired()])
            message = TextAreaField('Message', validators=[DataRequired()])
            submit = SubmitField('Submit', render_kw={'class': 'btn btn-dark'})

        class UserAnswer(self.db.Model):
            __tablename__ = f'user_answers' 
            id: Mapped[int] = mapped_column(Integer, primary_key=True, unique=True)
            user_id: Mapped[int] = mapped_column(Integer, nullable=False)
            question_id: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
            student: Mapped[int] = mapped_column(Integer, nullable=False)
            question: Mapped[str] = mapped_column(String(5000), nullable=False)
            answer: Mapped[str] = mapped_column(String(5000), nullable=True)
            created_at: Mapped[str] = mapped_column(String(250), nullable=False)
            updated_at: Mapped[str] = mapped_column(String(250), nullable=False)

            def to_dict(self):
                # DBを辞書タイプに変換する関数を自分で設定する必要がある
                return {column.name: getattr(self, column.name) for column in self.__table__.columns}

        class Questions(self.db.Model):
            __tablename__ = 'questions'
            id: Mapped[int] = mapped_column(Integer, primary_key=True, unique=True)
            category: Mapped[str] = mapped_column(String(250), nullable=False)
            depth: Mapped[str] = mapped_column(String(250), nullable=False)
            stage: Mapped[str] = mapped_column(String(250), nullable=False)
            question: Mapped[str] = mapped_column(String(5000), nullable=False, unique=True)
            answer: Mapped[str] = mapped_column(String(5000), nullable=True)
            created_at: Mapped[str] = mapped_column(String(250), nullable=False)
            updated_at: Mapped[str] = mapped_column(String(250), nullable=False)

            def to_dict(self):
                return {column.name: getattr(self, column.name) for column in self.__table__.columns}
        

        class Users(UserMixin, self.db.Model):
            __tablename__ = 'users'
            id: Mapped[int] = mapped_column(Integer, primary_key=True)
            username: Mapped[str] = mapped_column(String(250), nullable=False)
            email: Mapped[str] = mapped_column(String(250), nullable=False, unique=True)
            password: Mapped[str] = mapped_column(String(250), nullable=False)
            student: Mapped[int] = mapped_column(Integer, nullable=False)
            agreement: Mapped[int] = mapped_column(Integer, nullable=False)
            created_at: Mapped[str] = mapped_column(String(250), nullable=False)
            updated_at: Mapped[str] = mapped_column(String(250), nullable=False)

            def to_dict(self):
                return {column.name: getattr(self, column.name) for column in self.__table__.columns}


        self.UserAnswer = UserAnswer
        self.Questions = Questions
        self.Users = Users
        self.RegisterForm = RegisterForm
        self.LoginForm = LoginForm
        self.UpdateForm = UpdateForm
        self.ContactForm = ContactForm
        self.ChangePasswordForm = ChangePasswordForm
        self.current_random_question = []

    def create_new_table(self):
        with self.app.app_context():
            self.db.create_all()

    # --- User management -----
    def create_new_user(self, new_user):
        with self.app.app_context():
            result = self.db.session.execute(self.db.select(self.Users).where(self.Users.email == new_user["email"])).scalar()
            if result == None:                
                new_user = self.Users(
                    username=new_user["username"],
                    email=new_user["email"],
                    password=new_user["password"],
                    student=int(new_user["student"]),
                    agreement=1,
                    created_at= dt.datetime.now().strftime('%F %T'),
                    updated_at= dt.datetime.now().strftime('%F %T')
                )
                self.db.session.add(new_user)
                self.db.session.commit()
                print("New sccount created.")
                return True
            else:
                print("The account has been already created.")
                return False

    def let_them_login(self, user):
        try:
            result = self.db.session.execute(self.db.select(self.Users).where(self.Users.email == user["email"]))
            confirmed_user = result.scalar()
            if check_password_hash(confirmed_user.password, user["password"]):
                print(confirmed_user)
                return confirmed_user
            else:
                # パスワードが違う
                return "Failed to login. Please confirm your email address and password again."
        except Exception:
            # メールアドレスが違う（メッセージを変えるとメールアドレスの登録がばれるのでメアドとパスどちらが違うかわからないよう共通のメッセージを使う）
            return "Failed to login. Please confirm your email address and password again."

    def download_data(self, user):
        with self.app.app_context():
            all_posts = []
            result = (
            self.db.session.query(self.UserAnswer, self.Questions.category, self.Questions.depth)
            .join(self.Questions, self.UserAnswer.question_id == self.Questions.id)
            .filter(self.UserAnswer.user_id == user.id)
            .order_by(self.UserAnswer.updated_at.desc())
            .all()
            )
            for user_answer, category, depth in result:
                post_dict = {}
                post_dict['category'] = category
                post_dict['depth'] = depth
                post_dict['question'] = user_answer.question
                post_dict['answer'] = user_answer.answer
                post_dict['updated_at'] = user_answer.updated_at
                all_posts.append(post_dict)
        if not all_posts:
            return "No data."
        else:
            filename = f"who_are_you_userdata_{dt.datetime.now().strftime('%Y%m%d_%H%M')}.csv"
            with open(filename, "w", newline='', encoding='utf-8') as file:
                fieldnames = all_posts[0].keys() # 辞書のキーからフィールド名を取得
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader() # ヘッダー行を書き込む
                writer.writerows(all_posts)
                return filename
    
    def update_user_information(self, user_id, update_information):
        try:
            result = self.db.session.execute(
                self.db.update(self.Users)
                .where(self.Users.id == user_id)
                .values(**update_information, updated_at=dt.datetime.now().strftime('%F %T'))
            )
            self.db.session.commit()
            print(f"Update successfully.")
        except Exception as e:
            self.db.session.rollback()
            print(f"Error updating post: {e}")
            

    # --- Origin Questions -------
    def get_all_questions(self, current_user):
        with self.app.app_context():
            if current_user.is_authenticated:
                already_answered_ids = self.db.session.query(self.UserAnswer.question_id).filter(self.UserAnswer.id == current_user.id).all()
                already_answered_ids = [item[0] for item in already_answered_ids]
                all_posts = self.db.session.query(self.Questions).filter(
                    ~self.Questions.id.in_(already_answered_ids))
                return [post.to_dict() for post in all_posts]             
            else: 
                all_posts = self.Questions.query.all() 
                return [post.to_dict() for post in all_posts]          
        
    def pick_random_question(self, current_user):
        return random.choice(self.get_all_questions(current_user))

    # --- User Answer -------
    def get_all_posts(self, user_id):
        with self.app.app_context():
            all_posts = []
            result = (
            self.db.session.query(self.UserAnswer, self.Questions.category, self.Questions.depth)
            .join(self.Questions, self.UserAnswer.question_id == self.Questions.id)
            .filter(self.UserAnswer.user_id == user_id)
            .order_by(self.UserAnswer.updated_at.desc())
            .all()
            )
            for user_answer, category, depth in result:
                post_dict = user_answer.to_dict()
                post_dict['category'] = category
                post_dict['depth'] = depth
                all_posts.append(post_dict)
        return all_posts
    
    def add_post(self, question_id, user_answer, user_id, is_student):
        with self.app.app_context():
            question = self.db.session.execute(self.db.select(self.Questions).where(self.Questions.id == question_id)).scalar().to_dict()
            new_answer = self.UserAnswer(
                    user_id=user_id,
                    question_id=question_id,
                    student=is_student,
                    question=question["question"],
                    answer=user_answer,
                    created_at= dt.datetime.now().strftime('%F %T'),
                    updated_at= dt.datetime.now().strftime('%F %T')
                )
            self.db.session.add(new_answer)
            self.db.session.commit()
    
    def edit_post(self, question_id, user_answer, user_id):
        try:
            # update() メソッドを使って直接更新
            result = self.db.session.execute(
                self.db.update(self.UserAnswer)
                .where(
                    and_(
                        self.UserAnswer.question_id == question_id,
                        self.UserAnswer.user_id == user_id
                    )
                )
                .values(answer=user_answer, updated_at=dt.datetime.now().strftime('%F %T'))
            )
            self.db.session.commit()
            print(f"Update successfully.")
        except Exception as e:
            self.db.session.rollback()
            print(f"Error updating post: {e}")
            
    def delete_posts(self, question_id, user_id):
        with self.app.app_context():
            try:
                posts_to_delete = self.db.session.query(self.UserAnswer).filter(
                    self.UserAnswer.question_id == question_id,
                    self.UserAnswer.user_id == user_id
                    ).scalar()
                self.db.session.delete(posts_to_delete)
                self.db.session.commit()
                print("Deleted successfully.")
                return True
            except Exception as e: 
                self.db.session.rollback()  # エラー発生時はロールバック
                print(f"Error deleting posts: {e}")
                return False 


manager = DataManager()
send_email = send_email.SendEmail()
manager.create_new_table()

year = dt.datetime.now().year
app = manager.app

# Login control
@manager.login_manager.user_loader
def load_user(user_id):
    return manager.db.get_or_404(manager.Users, user_id)


@app.route('/')
def home():
    if not current_user.is_authenticated:
        current_user.username = None
        current_user.id = None
    new_random_q = manager.pick_random_question(current_user)
    manager.current_random_question = new_random_q
    user_answer_list = manager.get_all_posts(current_user.id)
    rendered_data=user_answer_list[:10]
    pages = math.ceil(len(user_answer_list)/10)
    current_page = 1
    return render_template("index.html",
                           question=manager.current_random_question, 
                           category=category, 
                           depth=depth, 
                           user_data=rendered_data, 
                           current_year=year,
                           pages = pages,
                           current_page=current_page,
                           logged_in=current_user.is_authenticated,
                           name = current_user.username
                           )

@app.route('/post=<id>', methods=["POST"])
@login_required
def get_new_record(id):
    if request.method == "POST":
        new_record = request.form.get("new_record")
        manager.add_post(question_id=id, user_answer=new_record, user_id=current_user.id, is_student=current_user.student)
        flash("Submit Successfuly.")
    return redirect(url_for("home"))


@app.route('/cat=<current_category>')
def filtered_category(current_category):
    user_answer_list = manager.get_all_posts(current_user.id)
    if current_category == "all":
        rendered_data=user_answer_list[:10]
    else:
        filtered_database = []
        for item in user_answer_list:
            if item["category"] == current_category:
                filtered_database.append(item)
        rendered_data=filtered_database[:10]
    pages = math.ceil(len(user_answer_list)/10)
    current_page = 1 
    return render_template("index.html",
                    question=manager.current_random_question,
                    category=category,
                    depth=depth,
                    user_data=rendered_data,
                    current_year=year,
                    pages = pages,
                    current_page=current_page,
                    logged_in=current_user.is_authenticated,
                    name = current_user.username
                    )

 
@app.route('/depth=<current_depth>')
def filtered_depth(current_depth):
    user_answer_list = manager.get_all_posts(current_user.id)
    if current_depth == "all":
        rendered_data=user_answer_list[:10]
    else:
        filtered_database=[]
        for item in user_answer_list:
            if item["depth"] == current_depth:
                filtered_database.append(item)
        rendered_data=filtered_database[:10]
    pages = math.ceil(len(user_answer_list)/10)
    current_page = 1
    return render_template("index.html",
                    question=manager.current_random_question,
                    category=category,
                    depth=depth,
                    user_data=rendered_data,
                    current_year=year,
                    pages = pages,
                    current_page=current_page,
                    logged_in=current_user.is_authenticated,
                    name = current_user.username)

@app.route('/sort=<sort>')
def sort(sort):
    user_answer_list = manager.get_all_posts(current_user.id)
    if sort == "latest":
        rendered_data = user_answer_list[:10]
    else:
        rendered_data=user_answer_list[::-1][:10]
    pages = math.ceil(len(user_answer_list)/10)
    current_page = 1
    return render_template("index.html",
                    question=manager.current_random_question,
                    category=category,
                    depth=depth,
                    user_data=rendered_data,
                    current_year=year,
                    pages = pages,
                    current_page=current_page,
                    logged_in=current_user.is_authenticated,
                    name = current_user.username)

@app.route('/page=<number>')
def pagenation(number):
    user_answer_list = manager.get_all_posts(current_user.id)
    rendered_data = user_answer_list[(int(number)-1)*10:(int(number))*10]
    pages = math.ceil(len(user_answer_list)/10)
    return render_template("index.html",
                    question=manager.current_random_question,
                    category=category,
                    depth=depth,
                    user_data=rendered_data,
                    current_year=year,
                    current_page=int(number),
                    pages=pages,
                    logged_in=current_user.is_authenticated,
                    name = current_user.username)


@app.route('/delete=<id>')
def delete(id):
    manager.delete_posts(question_id=id, user_id=current_user.id)
    flash("Deleted successfully.")
    return redirect(url_for("home"))

@app.route('/edit=<int:id>', methods=["GET", "POST"])
def edit(id):
    if request.method == "POST":
        new_record = request.form.get("new_record")
        manager.edit_post(question_id=id, user_answer=new_record, user_id=current_user.id)
        flash("Updated successfully.")
        return redirect(url_for("home"))
    else:
        user_answer_list = manager.get_all_posts(current_user.id)
        for data in user_answer_list:
            if data["question_id"] == id:
                target_data = data
        return render_template("edit.html",
                            question=target_data,
                            current_year=year, 
                            logged_in=current_user.is_authenticated, 
                            name = current_user.username)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = manager.RegisterForm()
    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=11
        )
        if form.agreement.data == "1":
            new_user= {
                "username": form.username.data,
                "email": form.email.data,
                "password": hash_and_salted_password,
                "student": form.student.data,
            }
            if manager.create_new_user(new_user):
                flash(f"Thanks for joining, {form.username.data.title()}! Please login and get started!")
                return redirect(url_for("login"))
            else:
                flash("You seem already have an account. Please login your account.")
                return redirect(url_for("login"))
        else:
            flash("We need your consent for Terms of Use.")
            return redirect(url_for("register"))
    return render_template('register.html', form=form,
                                current_year=year)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = manager.LoginForm()
    if form.validate_on_submit():
        user= {
                "email": form.email.data,
                "password": form.password.data,
            }
        confirmed_user =  manager.let_them_login(user)
        if type(confirmed_user) == str:
            flash(confirmed_user)
            return render_template('login.html', form=form)            
        else:
            login_user(confirmed_user)
            flash(f"Welcome back, {current_user.username.title()}!")
            return redirect(url_for("home"))       
    else:
        return render_template("login.html", form=form,
                                current_year=year)

@app.route('/logout')
def logout():
    logout_user()
    flash("Logged out successfully.")
    return redirect(url_for("home"))

@app.route('/mypage')
@login_required
def mypage():
    return render_template("mypage.html", 
                           logged_in=current_user.is_authenticated, 
                           name = current_user.username,
                           current_year=year,
                           )

@app.route('/download')
@login_required
def download():
    result = manager.download_data(current_user)
    if result != "No data.":
        try:
            return send_file(path_or_file=result, as_attachment=True)
        finally:
            os.remove(result)
            flash("Downloaded a file successfully.")
    else:
        flash("No data.")
    return redirect(url_for('mypage'))


@app.route('/settings', methods=["GET", "POST"])
@login_required
def settings():
    form = manager.UpdateForm()
    if form.validate_on_submit():
        update_information = {}
        if form.email.data != "":
            update_information["email"] = form.email.data
        if form.username.data != "":
            update_information["username"] = form.username.data
        if form.student.data != "None":
            update_information["student"] = int(form.student.data)
        if update_information != {}:
            manager.update_user_information(user_id=current_user.id, update_information=update_information)
        flash("Updated your information successfully.")
        return redirect(url_for('mypage'))
    else:
        return render_template("settings.html", 
                                form=form,
                                logged_in=current_user.is_authenticated, 
                                name = current_user.username,
                                current_year=year)

@app.route('/reset', methods=["GET", "POST"])
@login_required
def change_password():
    form = manager.ChangePasswordForm()
    if form.validate_on_submit():
        print(form.new_password.data)
        if check_password_hash(current_user.password, form.current_password.data):
            hash_and_salted_password = generate_password_hash(
                form.new_password.data,
                method='pbkdf2:sha256',
                salt_length=11
            )
            update_information = {"password": hash_and_salted_password}
            manager.update_user_information(user_id=current_user.id, update_information=update_information)
            logout_user()
            flash("Updated the password successfully. Please login with the new password.")
            return redirect(url_for("login"))        
        else:
            flash("The current password is wrong. Please try again.")
            return render_template("password.html",
                                form=form,
                                logged_in=current_user.is_authenticated,
                                current_year=year,
                                name = current_user.username)      
    else:
        return render_template("password.html",
                                form=form,
                                logged_in=current_user.is_authenticated,
                                current_year=year,
                                name = current_user.username)

@app.route('/contact', methods=["GET", "POST"])
def contact():
    if not current_user.is_authenticated:
        current_user.username = None
        current_user.id = None
    form = manager.ContactForm()
    if form.validate_on_submit():
        inquiry = {
            "name":form.name.data,
            "email":form.email.data,
            "category":form.category.data,
            "message":form.message.data
        }
        send_email.send_email(inquiry)
        flash("Your message submitted successfully.")
        return redirect(url_for('home'))
    else:
        return render_template("contact.html", 
                                form=form,
                                logged_in=current_user.is_authenticated, 
                                name = current_user.username,
                                current_year=year)

@app.route('/about')
def about():
     if not current_user.is_authenticated:
        current_user.username = None
        current_user.id = None
     return render_template("about.html", 
                                logged_in=current_user.is_authenticated, 
                                name = current_user.username,
                                current_year=year)

@app.route('/help')
def help():
     if not current_user.is_authenticated:
        current_user.username = None
        current_user.id = None
     return render_template("help.html", 
                                logged_in=current_user.is_authenticated, 
                                name = current_user.username,
                                current_year=year)

@app.route('/termsofuse')
def terms_of_use():
     if not current_user.is_authenticated:
        current_user.username = None
        current_user.id = None
     return render_template("terms_of_use.html", 
                                logged_in=current_user.is_authenticated, 
                                name = current_user.username,
                                current_year=year)

if __name__ == "__main__":
    app.run(debug=False)
    # app.run(host='127.0.0.1', port=5050, debug=True)
from os.path import join, dirname, realpath
import os
from flask_login import  login_required, LoginManager, UserMixin, login_manager, login_user, current_user, logout_user
from flask import Flask, request, send_from_directory, session, render_template, url_for, flash, get_flashed_messages, message_flashed
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import PY3, Bcrypt
from sqlalchemy.orm import relationship
from flask_wtf import Form
from wtforms import StringField, PasswordField, validators
from werkzeug.utils import redirect, secure_filename
from wtforms.fields.numeric import IntegerField
from wtforms.fields.simple import EmailField, SubmitField, FileField







app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///storage.db'

# Secret Key!
app.config['SECRET_KEY'] = "my super secret key that no one is supposed to know"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Initialize The Database
db = SQLAlchemy(app)
with app.app_context():
    db.create_all()



UPLOAD_FOLDER = join(dirname(realpath(__file__)), 'static/uploads/..')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Login to Continue"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':       
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            if bcrypt.check_password_hash(user.password, request.form['password']):
                login_user(user)
                return redirect(url_for('home'))
            else:
                
                flash(f'Incorrect password')
                return redirect(url_for('reset'))
            
        return redirect(url_for('signup'))
    return render_template('login.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset():
    form = Reset(request.form)
    if request.method == 'POST':
        user =  User.query.filter_by(username=form.username.data).first()
        if user:
            try:
                hashed_password = bcrypt.generate_password_hash(form.password.data)
                user.password = hashed_password
                db.session.commit()
                flash(f'Password reset successful')
                return redirect(url_for('login'))
            except:
                return "<h1>Your password reset failed</h1>"
        "<h1>Your account doesnt exist</h1>"
        return redirect(url_for('signup'))
    return render_template('reset_password.html', form=form)

@app.route('/logout')
@login_required
def logout():
   logout_user()
   return redirect(url_for('index'))

@app.route('/account')
@login_required
def account():
    return render_template("account.html", user=User.query.filter_by(id=current_user.id).first())

    
@app.route('/update_account', methods=['GET', 'POST'])
@login_required
def update():
    user = User.query.get(current_user.id)
    form = EditProfileForm(request.form)
    if request.method == 'POST':
        user.name = form.name.data
        user.email = form.email.data
        user.username = form.username.data        
        db.session.commit()
        return redirect(url_for('account'))
    return render_template('edit_profile.html', form=form, user=user)


@app.route('/delete_account')
@login_required
def delete_account():
    seller = Seller.query.filter_by(id=current_user.id).first()
    user  = User.query.filter_by(id=current_user.id).first()
    if seller:
        # os.remove(os.path.join('static/uploads/',  current_user.name))
        # os.remove(current_user.name)
        db.session.delete(seller), db.session.delete(user)
        db.session.commit()
    db.session.delete(user)
    db.session.commit()
    logout_user()
    return redirect(url_for('index'))


@app.route("/delete/<int:id>")
@login_required
def delete_product(id):
    seller = User.query.filter_by(id=current_user.id).first()
    work = Work.query.filter_by(seller_id=seller.id).first()
    if work and seller:
        db.session.delete(work)
        db.session.commit()
        flash(f"Success delete")
        return redirect(url_for('sellers'))
    flash(f"Failed to delete")
    return redirect(url_for('sellers')) 



@app.route('/home')
@login_required
def home():
    search = request.args.get('search')
    service = request.args.get('service')
    
    if search:
        sellers = Seller.query.filter(Seller.flexibility.contains(search) | Seller.location.contains(search) | Seller.type_work.contains(search))
        work = Work.query.all() 
            
    
    elif service:
        sellers=Seller.query.all()
        work = Work.query.filter(Work.name.contains(service))
        return render_template('home.html',   work=work, sellers=sellers )
    elif not search and not service:
        work=Work.query.all()
        sellers=Seller.query.all()  
        return render_template('home.html',   work=work, sellers=sellers )

        
    else:
        work=Work.query.all()
        sellers=Seller.query.all()  
    return render_template('home.html',   work=work, sellers=sellers )


@app.route('/sellers')
@login_required
def sellers():
    seller = Seller.query.filter_by(id=current_user.id).first()
    if not seller:
         return redirect(url_for('register'))
    work = Work.query.filter_by(seller_id=current_user.id).all()
    return render_template('sellers.html', work=work, seller = Seller.query.filter_by(username=current_user.username).first() )   
      
@app.route('/update_work/<int:id>', methods=['GET', 'POST'])
@login_required
def update_product(id):
    
    work = Work.query.get_or_404(id)
    form = EditProduct(request.form)
    if request.method == 'POST':
        work.name = form.name.data
       
        work.price = form.price.data
       
        work.description = form.description.data
        
        db.session.commit()
        return redirect(url_for('sellers'))
       
    return render_template('update_product.html', form=form, work=work)    




@app.route('/add_product', methods=['POST', 'GET'])
@login_required
def add_product():
    form = Addwork()
    seller = Seller.query.filter_by(username=current_user.username).first()      
    if request.method == 'POST':
        if 'file' not in request.files:
            flash(f'No file part', 'error')
            return redirect(url_for('sellers'))
    
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return render_template('sellers.html', work = Work.query.filter_by(seller_id=current_user.id).all(), seller = Seller.query.filter_by(username=current_user.username).first())
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(seller.folder, filename))
             
            
            new_work = Work(name=request.form['name'], img=filename,   price=request.form['price'], description=request.form['description'], seller_id=current_user.id)
            
            try:
                db.session.add(new_work)
                db.session.commit()
                
                return render_template('sellers.html', work=Work.query.filter_by(seller_id=current_user.id).all(), seller = Seller.query.filter_by(username=current_user.username).first())
            except:
                return "<h1>Failed to add your new product</h1>"
    return render_template('add_product.html', form=form)            


   


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    form = Registration()
    seller = Seller.query.filter_by(username=current_user.id).first()
    if seller:
        return redirect(url_for('sellers'))
    if request.method == 'POST':    
        folder = (os.path.join(app.config['UPLOAD_FOLDER'],  current_user.name))
        os.mkdir(folder)
    
        new_seller = Seller(name=current_user.name, flexibility=request.form['flexibility'], location=request.form['location'],  folder=folder, email=current_user.email, username=current_user.username, type_work=request.form['type_work'], phone=request.form['phone'])
        try:
            db.session.add(new_seller)
            db.session.commit()
            return redirect(url_for('sellers'))
        except:
            flash(f'Failed to register your business')
            return redirect(url_for('home'))
    
    return render_template('register.html', form=form)



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form=Signup(request.form)
    if request.method == 'POST' and form.validate():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user = User(username=form.username.data,   email=form.email.data, name=form.name.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/')
def index():
    return render_template('index.html')





#first create the route
@app.route('/uploads/<path:filename>')
def download_file(filename):
    return send_from_directory(os.path.abspath(UPLOAD_FOLDER), filename, as_attachment=True)

#add this to the template inside of an image tag


# ERROR PAGES

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404

@app.errorhandler(500)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('500.html'), 500


class Seller(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), unique=True)
    email = db.Column(db.String(30), unique=True)
    location = db.Column(db.String(30), unique=True)
    flexibility = db.Column(db.String(30), unique=True)
    username = db.Column(db.String(30), unique=True)
    phone = db.Column(db.Integer, nullable=False)
    work =  db.relationship('Work', backref='seller', cascade="all, delete-orphan",  lazy=True)
    type_work = db.Column(db.String(50), nullable=False)
    folder = db.Column(db.String(256), unique=True)

class Work(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), unique=True)
    price = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(100))
    seller_id = db.Column(db.Integer, db.ForeignKey('seller.id'))
    img =  db.Column(db.String(100))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), unique=True)
    email = db.Column(db.String(30), unique=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(256), nullable=False)


class EditProfileForm(Form):
    name = StringField('Name',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    email = EmailField('Email',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    username = StringField('Username',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    submit = SubmitField("Update Account Details")

class Reset(Form):
    username = StringField('Username',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    password = PasswordField('password',  validators=[validators.input_required()])
    confirm= PasswordField('Confirm',  validators=[validators.input_required(), validators.Length(min=1, max=50), validators.EqualTo('password',
                             message="Passwords must match")])
    submit = SubmitField("RESET")
    
class EditProduct(Form):
    name = StringField('Name',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    price = IntegerField('Price',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    description = StringField('description',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    submit = SubmitField("Update")

    
class Addwork(Form):
    name = StringField('Name',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    price = StringField('price',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    description = StringField('Description',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    file = FileField("Image")
    submit = SubmitField("Add Work")

    
class Registration(Form):
    phone = StringField('Phone',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    type_work = StringField("Type of Service", validators=[validators.input_required()])
    location = StringField("Location in Kigali", validators=[validators.input_required()])
    flexibility = StringField("Mobile or Salon: Can you travel for customers or they come to you. ", validators=[validators.input_required()])
    submit = SubmitField("Register")


class Signup(Form):
    name = StringField('Name',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    email = StringField('Email',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    username = StringField('Username',  validators=[validators.input_required(), validators.Length(min=1, max=50)])
    
    password = PasswordField('password',  validators=[validators.input_required()])
    confirm= PasswordField('Confirm',  validators=[validators.input_required(), validators.Length(min=1, max=50), validators.EqualTo('password',
                             message="Passwords must match")])
    submit = SubmitField("Register")

# ROUTES 



if __name__ == "__main__":
    app.run()
    db.create_all()


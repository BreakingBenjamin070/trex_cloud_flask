from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import User, db
from forms import RegistrationForm, LoginForm

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app) 
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('lk')) 
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('lk'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data) 
            return redirect(url_for('lk'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/lk)
@login_required 
def lk():
    return render_template(lk.html')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/services')
def services():
    cloud_services = ["Виртуальные серверы", "Облачное хранилище", "Kubernetes"]
    return render_template('services.html', services=cloud_services)

@app.route('/servers')
def list_servers():
    servers = [
        {"id": 1, "name": "GPU-сервер", "type": "GPU"},
        {"id": 2, "name": "Хранилище данных", "type": "Storage"},
        {"id": 3, "name": "Вычислительный сервер", "type": "Compute"}
    ]

    server_type = request.args.get('type')
    if server_type:
        servers = [s for s in servers if s["type"] == server_type]

    return render_template('servers.html', servers=servers)

@app.route('/server/<int:server_id>')
def server_details(server_id):
    servers = {
        1: {"name": "GPU-сервер", "desc": "Идеален для машинного обучения"},
        2: {"name": "Хранилище данных", "desc": "Надежное облачное хранилище"},
        3: {"name": "Вычислительный сервер", "desc": "Мощный сервер для вычислений"}
    }
    
    server = servers.get(server_id)
    if not server:
        return render_template('404.html'), 404

    return render_template('server_details.html', server=server)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)



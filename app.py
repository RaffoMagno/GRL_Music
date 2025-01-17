from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_pymongo import PyMongo
from models import db, User
from flask_bcrypt import Bcrypt
import os
import re
from flask import send_from_directory

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'key_sessione_user'

# Configurazione database relazionale
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

# Configurazione database MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/musicDB"
mongo = PyMongo(app)

# Configurazione cartella di upload
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/home')
@login_required
def home():
    # Recupera tutte le canzoni dal database MongoDB
    songs = list(mongo.db.songs.find())
    return render_template('home.html', username=current_user.username, songs=songs)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logout effettuato con successo.", "success")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if controllaPassword(password):
            if User.query.filter_by(username=username).first():
                flash("Questo username è già in uso.", "error")
                return render_template('register.html')

            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Registrazione avvenuta con successo!", "success")
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            #flash("Login effettuato con successo!", "success")
            return redirect(url_for('home'))
        flash("Credenziali non valide!", "error")
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/indietro', methods=['GET'])
def indietro():
    return redirect(url_for('home'))

@app.route('/add_song', methods=['GET', 'POST'])
@login_required
def add_song():
    if request.method == 'POST':
        title = request.form['title']
        artist = request.form['artist']
        audio_file = request.files['audio']

        if audio_file:
            filename = audio_file.filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            audio_file.save(filepath)

            # Salva i dati nel database MongoDB
            mongo.db.songs.insert_one({
                'title': title,
                'artist': artist,
                'filename': filename
            })
            flash("Canzone aggiunta con successo!", "success")
            return redirect(url_for('home'))

    return render_template('add_song.html')

@app.route('/play/<filename>', methods=['GET'])
@login_required
def play_song(filename):
    # Restituisce il file audio dalla cartella di upload
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        flash("File non trovato.", "error")
        return redirect(url_for('home'))

def controllaPassword(password):
    if len(password) < 8:
        flash("La password deve contenere almeno 8 caratteri.", "error")
        return False
    if not re.search(r"[A-Z]", password):
        flash("La password deve contenere almeno una lettera maiuscola.", "error")
        return False
    if not re.search(r"[a-z]", password):
        flash("La password deve contenere almeno una lettera minuscola.", "error")
        return False
    if not re.search(r"[0-9]", password):
        flash("La password deve contenere almeno un numero.", "error")
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        flash("La password deve contenere almeno un carattere speciale.", "error")
        return False
    return True

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
import os
from werkzeug.security import check_password_hash, generate_password_hash
from models import User

app = Flask(__name__)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.config["MONGO_URI"] = "mongodb://localhost:27017/musicDB"
app.secret_key = os.urandom(24) 
mongo = PyMongo(app)

login_manager.init_app(app)


@login_manager.user_loader
def load_user(username):
    return User.get(username) 

@app.route('/home')
@login_required
def home():
    songs = mongo.db.songs.find()
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

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        existing_user = mongo.db.users.find_one({"username": username})
        if existing_user:
            flash("Questo username è già in uso.", "error")
            return render_template('register.html')

        mongo.db.users.insert_one({
            "username": username,
            "password": hashed_password
        })
        flash("Registrazione avvenuta con successo!", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.get(username)
        if user and bcrypt.check_password_hash(user.password, password): 
            login_user(user)
            flash("Login effettuato con successo!", "success")
            return redirect(url_for('home'))
        flash("Credenziali non valide!", "error")
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/add_song', methods=['GET', 'POST'])
@login_required
def add_song():
    if request.method == 'POST':
        title = request.form['title']
        artist = request.form['artist']
        audio = request.files['audio']

        if audio:
            audio_path = os.path.join('uploads', audio.filename)
            audio.save(audio_path)  
            mongo.db.songs.insert_one({
                "title": title,
                "artist": artist,
                "filename": audio.filename,
                "user": current_user.username
            })
            flash("Canzone aggiunta con successo!", "success")
            return redirect(url_for('home'))
        else:
            flash("Errore: nessun file audio selezionato.", "error")
    return render_template('add_song.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

if __name__ == '__main__':
    app.run(debug=True)

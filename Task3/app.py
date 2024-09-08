from flask import Flask, request, render_template, redirect, url_for, flash
import sqlite3
import re
import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  


def connect_db():
    return sqlite3.connect('user_data.db')


def create_users_table():
    with connect_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )''')
        conn.commit()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))
        
        
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!', 'error')
            return redirect(url_for('register'))

        
        if len(password) < 8 or not re.match(r'[A-Za-z0-9@#$%^&+=]', password):
            flash('Password must be at least 8 characters long and contain letters, numbers, and special characters!', 'error')
            return redirect(url_for('register'))

       
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        
        try:
            with connect_db() as conn:
                conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                             (username, email, hashed_password))
                conn.commit()
                flash('Registration successful!', 'success')
                return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('User already exists!', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
       
        if not email or not password:
            flash('Email and password are required!', 'error')
            return redirect(url_for('login'))
        
        with connect_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if user and bcrypt.checkpw(password.encode(), user[3].encode()):
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials!', 'error')
                return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    return 'Welcome to your dashboard!'

if __name__ == '__main__':
    create_users_table()
    app.run(debug=True)

# this code is conducted by Barsha Saha

from flask import Flask, request, redirect, session, render_template_string, jsonify
import sqlite3
import os
import hashlib
import random
import time
import jwt

app = Flask(__name__)
app.secret_key = 'super_s3cr3t_k3y_f0r_sh0pp1ng_s1t3'  # Intentionally exposed secret key
JWT_SECRET = 'jwt_s3cr3t_k3y_d0nt_l34k_th1s'  # Second secret for JWT tokens

# Database setup
def init_db():
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    # Users table with admin account
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        role TEXT DEFAULT 'customer',
        balance REAL DEFAULT 100.0
    )''')
    
    # Create admin with weak password
    admin_pass = 'P@ssW0rd'  # Intentionally weak password
    cursor.execute("UPDATE users SET balance = 999999999999999999999999999999999999999999999999999999999999999999999999999999999.99 WHERE username = 'admin'")
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, role, balance) VALUES (?, ?, ?, ?, ?)", 
                  ('admin', admin_pass, 'admin@eshop.ctf', 'admin', 9999999999999999999999999.99))
    
    # Products table
    cursor.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        description TEXT,
        price REAL,
        stock INTEGER,
        image_url TEXT
    )''')
    
    # Sample products
    products = [
        ('Premium Laptop', 'High-end gaming laptop with RTX 4090', 1999.99, 10, '/static/laptop.jpg'),
        ('Smartphone Pro', 'Latest flagship smartphone', 899.99, 25, '/static/phone.jpg'),
        ('Wireless Headphones', 'Noise-cancelling headphones', 199.99, 50, '/static/headphones.jpg'),
        ('Smart Watch', 'Fitness and health tracking', 249.99, 30, '/static/watch.jpg'),
        ('Flag Hint', 'Get a hint for finding the flag!', 999.99, 1, '/static/hint.jpg'),
        ('Professional Drone', ' Advanced aerial device with a high-resolution camera. ', 9999.99, 1, '/static/flag.jpg')
    ]
    
    for product in products:
        cursor.execute("INSERT OR IGNORE INTO products (name, description, price, stock, image_url) VALUES (?, ?, ?, ?, ?)", product)
    
    # Orders table
    cursor.execute('''CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        product_id INTEGER,
        quantity INTEGER,
        date TEXT,
        status TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (product_id) REFERENCES products (id)
    )''')
    
    # Secret flags table (hidden from normal users)
    cursor.execute('''CREATE TABLE IF NOT EXISTS flags (
        id INTEGER PRIMARY KEY,
        flag_name TEXT,
        flag_value TEXT
    )''')
    
    # Insert the real flag
    cursor.execute("INSERT OR IGNORE INTO flags (flag_name, flag_value) VALUES (?, ?)", 
                  ('main_flag', 'expX{Sh0pp1ng_C4rt_Expl01t_M4st3r}'))
    
    # Comments table with SQL injection vulnerability
    cursor.execute('''CREATE TABLE IF NOT EXISTS product_comments (
        id INTEGER PRIMARY KEY,
        product_id INTEGER,
        username TEXT,
        comment TEXT,
        rating INTEGER,
        FOREIGN KEY (product_id) REFERENCES products (id)
    )''')
    
    # Some sample comments
    comments = [
        (1, 'user123', 'Great laptop, very fast!', 5),
        (1, 'gamer456', 'Amazing for gaming!', 5),
        (2, 'phonelover', 'Love this phone, great camera!', 4),
        (3, 'musicfan', 'Sound quality is amazing!', 5)
    ]
    
    for comment in comments:
        cursor.execute("INSERT OR IGNORE INTO product_comments (product_id, username, comment, rating) VALUES (?, ?, ?, ?)", comment)
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Routes
@app.route('/')
def home():
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()

    # Debug: Print session role
    print(f"Session Role: {session.get('role')}")

    # Role-based product filtering
    if 'role' in session and session['role'] == 'admin':
        query = "SELECT id, name, description, price, image_url FROM products"
    else:
        query = "SELECT id, name, description, price, image_url FROM products WHERE name NOT IN ('Flag Hint', 'Professional Drone') AND id NOT IN (5, 6)"

    # Debug: Print SQL query
    print(f"Executing Query: {query}")
    
    cursor.execute(query)
    products = cursor.fetchall()
    conn.close()

    # Debug: Print fetched products
    print(f"Fetched Products: {products}")

    # Get user details
    username = session.get('username')
    role = session.get('role', 'visitor')
    balance = session.get('balance', 0.0)
    
    # Template with intentional XSS vulnerability in the search function
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>E-Shop CTF</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                header {
                    background-color: #333;
                    color: white;
                    padding: 10px 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                nav a {
                    color: white;
                    margin-left: 15px;
                    text-decoration: none;
                }
                .container {
                    max-width: 1200px;
                    margin: 20px auto;
                    padding: 0 20px;
                }
                .products {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    grid-gap: 20px;
                }
                .product-card {
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    padding: 15px;
                    background-color: white;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .product-card h3 {
                    margin-top: 0;
                }
                .price {
                    font-weight: bold;
                    color: #e63946;
                }
                .search-bar {
                    margin: 20px 0;
                    display: flex;
                }
                .search-bar input {
                    flex-grow: 1;
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px 0 0 4px;
                }
                .search-bar button {
                    padding: 10px 15px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 0 4px 4px 0;
                    cursor: pointer;
                }
                .button {
                    display: inline-block;
                    padding: 8px 16px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    margin-top: 10px;
                }
                .user-info {
                    color: white;
                    display: flex;
                    align-items: center;
                }
                .user-info span {
                    margin-right: 15px;
                }
                .search-results {
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <header>
                <h1>E-Shop CTF</h1>
                <div class="user-info">
                    {% if username %}
                        <span>Welcome, {{ username }}!</span>
                        <span>Role: {{ role }}</span>
                        <span>Balance: ${{ "%.2f"|format(balance) }}</span>
                        <a href="/cart">Cart</a>
                        <a href="/account">My Account</a>
                        <a href="/logout">Logout</a>
                    {% else %}
                        <nav>
                            <a href="/login">Login</a>
                            <a href="/register">Register</a>
                        </nav>
                    {% endif %}
                </div>
            </header>
            
            <div class="container">
                <form class="search-bar" action="/search" method="get">
                    <input type="text" name="q" placeholder="Search products...">
                    <button type="submit">Search</button>
                </form>
                
                <!-- XSS vulnerability: search results displayed without escaping -->
                {% if request.args.get('q') %}
                <div class="search-results">
                    <h2>Search results for: {{ request.args.get('q') }}</h2> <!-- Removed |safe -->
                </div>
                {% endif %}
                
                <h2>Our Products</h2>
                <div class="products">
                    {% for product in products %}
                        <div class="product-card">
                            <h3>{{ product[1] }}</h3>
                            <p>{{ product[2] }}</p>
                            <p class="price">${{ "%.2f"|format(product[3]) }}</p>
                            <a href="/product/{{ product[0] }}" class="button">View Details</a>
                            <form action="/add_to_cart" method="post" style="display: inline;">
                                <input type="hidden" name="product_id" value="{{ product[0] }}">
                                <button type="submit" class="button">Add to Cart</button>
                            </form>
                        </div>
                    {% endfor %}
                </div>
            </div>
        </body>
        </html>
    ''', products=products, username=username, role=role, balance=balance, request=request)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Use parameterized queries to prevent SQL injection
        conn = sqlite3.connect('shop.db')
        cursor = conn.cursor()
        query = "SELECT id, username, role, balance FROM users WHERE username=? AND password=?"
        
        try:
            cursor.execute(query, (username, password))
            user = cursor.fetchone()
            
            if user:
                session['username'] = user[1]
                session['user_id'] = user[0]
                session['role'] = user[2]
                
                # Generate secure JWT token
                token = jwt.encode({
                    'user_id': user[0],
                    'username': user[1],
                    'role': user[2],
                    'iat': int(time.time()),
                    'exp': int(time.time()) + 3600,  # Expires in 1 hour
                     # Unique token ID
                }, JWT_SECRET, algorithm='HS256')
                
                session['token'] = token
                
                # Set secure cookie
                redirect_response = redirect('/')
                redirect_response.set_cookie(
                    'auth_token', 
                    token,
                    httponly=True,     # Prevents JavaScript access
                    secure=True,       # Only sent over HTTPS
                    samesite='Lax',    # CSRF protection
                    max_age=3600       # Cookie expiration
                )
                conn.close()
                return redirect_response
            else:
                error_message = "Invalid credentials"
        except sqlite3.Error:
            # Generic error message to avoid information disclosure
            error_message = "An error occurred during login"
        finally:
            conn.close()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - E-Shop CTF</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .login-container {
                    background-color: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    width: 350px;
                }
                h1 {
                    text-align: center;
                    margin-bottom: 20px;
                }
                .form-group {
                    margin-bottom: 15px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                    font-weight: bold;
                }
                input[type="text"],
                input[type="password"] {
                    width: 100%;
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                .btn {
                    width: 100%;
                    padding: 10px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                }
                .btn:hover {
                    background-color: #45a049;
                }
                .error {
                    color: red;
                    margin-bottom: 15px;
                }
                .links {
                    text-align: center;
                    margin-top: 15px;
                }
                .links a {
                    color: #4CAF50;
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <h1>Login</h1>
                {% if error_message %}
                    <div class="error">{{ error_message }}</div>
                {% endif %}
                <form method="post">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn">Login</button>
                </form>
                <div class="links">
                    <a href="/register">Don't have an account? Register</a><br>
                    <a href="/">Back to Homepage</a>
                </div>
                <!-- Hidden comment with hint: Try SQL Injection with admin' -- -->
            </div>
        </body>
        </html>
    ''', error_message=error_message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error_message = None
    success_message = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if len(password) < 6:
            error_message = "Password must be at least 6 characters long"
        else:
            conn = sqlite3.connect('shop.db')
            cursor = conn.cursor()
            
            try:
                cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                              (username, password, email))
                conn.commit()
                success_message = "Registration successful! You can now login."
            except sqlite3.IntegrityError:
                error_message = "Username already exists. Please choose another one."
            
            conn.close()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Register - E-Shop CTF</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .register-container {
                    background-color: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    width: 350px;
                }
                h1 {
                    text-align: center;
                    margin-bottom: 20px;
                }
                .form-group {
                    margin-bottom: 15px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                    font-weight: bold;
                }
                input[type="text"],
                input[type="password"],
                input[type="email"] {
                    width: 100%;
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                .btn {
                    width: 100%;
                    padding: 10px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                }
                .btn:hover {
                    background-color: #45a049;
                }
                .error {
                    color: red;
                    margin-bottom: 15px;
                }
                .success {
                    color: green;
                    margin-bottom: 15px;
                }
                .links {
                    text-align: center;
                    margin-top: 15px;
                }
                .links a {
                    color: #4CAF50;
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <div class="register-container">
                <h1>Register</h1>
                {% if error_message %}
                    <div class="error">{{ error_message }}</div>
                {% endif %}
                {% if success_message %}
                    <div class="success">{{ success_message }}</div>
                {% endif %}
                <form method="post">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn">Register</button>
                </form>
                <div class="links">
                    <a href="/login">Already have an account? Login</a><br>
                    <a href="/">Back to Homepage</a>
                </div>
            </div>
        </body>
        </html>
    ''', error_message=error_message, success_message=success_message)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    # Get product details
    cursor.execute("SELECT * FROM products WHERE id=?", (product_id,))
    product = cursor.fetchone()

    # Block access to product ID 6 for non-admins
    if product[0] == 6 and session.get('role') != 'admin':
        return "Product not found", 404
    
    if not product:
        conn.close()
        return "Product not found", 404
    
    # Get product comments - SQL Injection vulnerability
    query = f"SELECT * FROM product_comments WHERE product_id={product_id}"
    cursor.execute(query)
    comments = cursor.fetchall()
    
    conn.close()
    
    username = session.get('username', None)
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ product[1] }} - E-Shop CTF</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                header {
                    background-color: #333;
                    color: white;
                    padding: 10px 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                nav a {
                    color: white;
                    margin-left: 15px;
                    text-decoration: none;
                }
                .container {
                    max-width: 1200px;
                    margin: 20px auto;
                    padding: 20px;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .product-detail {
                    display: flex;
                    margin-bottom: 30px;
                }
                .product-image {
                    width: 40%;
                    padding-right: 20px;
                }
                .product-info {
                    width: 60%;
                }
                .price {
                    font-size: 24px;
                    font-weight: bold;
                    color: #e63946;
                    margin: 15px 0;
                }
                .button {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    border: none;
                    font-size: 16px;
                    cursor: pointer;
                }
                .comments-section {
                    margin-top: 30px;
                    border-top: 1px solid #ddd;
                    padding-top: 20px;
                }
                .comment {
                    border-bottom: 1px solid #eee;
                    padding: 15px 0;
                }
                .comment-form {
                    margin-top: 20px;
                }
                .form-group {
                    margin-bottom: 15px;
                }
                label {
                    display: block;
                    margin-bottom: 5px;
                }
                textarea {
                    width: 100%;
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    resize: vertical;
                }
                .rating {
                    margin-bottom: 15px;
                }
                .rating input {
                    margin-right: 10px;
                }
            </style>
        </head>
        <body>
            <header>
                <h1>E-Shop CTF</h1>
                <div>
                    {% if username %}
                        <span style="color: white; margin-right: 15px;">Welcome, {{ username }}!</span>
                        <a href="/cart">Cart</a>
                        <a href="/account">My Account</a>
                        <a href="/logout">Logout</a>
                    {% else %}
                        <nav>
                            <a href="/login">Login</a>
                            <a href="/register">Register</a>
                        </nav>
                    {% endif %}
                </div>
            </header>
            
            <div class="container">
                <div class="product-detail">
                    <div class="product-image">
                        <img src="#" alt="{{ product[1] }}" width="100%">
                    </div>
                    <div class="product-info">
                        <h1>{{ product[1] }}</h1>
                        <p>{{ product[2] }}</p>
                        <p class="price">${{ "%.2f"|format(product[3]) }}</p>
                        <p>In stock: {{ product[4] }}</p>
                        
                        <form action="/add_to_cart" method="post">
                            <input type="hidden" name="product_id" value="{{ product[0] }}">
                            <button type="submit" class="button">Add to Cart</button>
                        </form>
                    </div>
                </div>
                
                <div class="comments-section">
                    <h2>Customer Reviews</h2>
                    
                    {% if comments %}
                        {% for comment in comments %}
                            <div class="comment">
                                <h4>{{ comment[2] }}</h4>
                                <p>Rating: {{ comment[4] }}/5</p>
                                <p>{{ comment[3] }}</p>
                            </div>
                        {% endfor %}
                    {% else %}
                        <p>No reviews yet. Be the first to review this product!</p>
                    {% endif %}
                    
                    {% if username %}
                        <div class="comment-form">
                            <h3>Leave a Review</h3>
                            <form action="/add_comment" method="post">
                                <input type="hidden" name="product_id" value="{{ product[0] }}">
                                
                                <div class="rating">
                                    <label>Rating:</label>
                                    <input type="radio" name="rating" value="5" id="rating5" checked>
                                    <label for="rating5">5</label>
                                    <input type="radio" name="rating" value="4" id="rating4">
                                    <label for="rating4">4</label>
                                    <input type="radio" name="rating" value="3" id="rating3">
                                    <label for="rating3">3</label>
                                    <input type="radio" name="rating" value="2" id="rating2">
                                    <label for="rating2">2</label>
                                    <input type="radio" name="rating" value="1" id="rating1">
                                    <label for="rating1">1</label>
                                </div>
                                
                                <div class="form-group">
                                    <label for="comment">Your Review:</label>
                                    <textarea id="comment" name="comment" rows="4" required></textarea>
                                </div>
                                
                                <button type="submit" class="button">Submit Review</button>
                            </form>
                        </div>
                    {% endif %}
                </div>
            </div>
        </body>
        </html>
    ''', product=product, comments=comments, username=username)

@app.route('/add_comment', methods=['POST'])
def add_comment():
    if 'username' not in session:
        return redirect('/login')
    
    product_id = request.form.get('product_id')
    comment = request.form.get('comment')
    rating = request.form.get('rating', 5)
    
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    # Vulnerable comment insertion with user input
    username = session.get('username')
    
    # Intentionally vulnerable to SQLi and stored XSS
    cursor.execute(f"INSERT INTO product_comments (product_id, username, comment, rating) VALUES ({product_id}, '{username}', '{comment}', {rating})")
    
    conn.commit()
    conn.close()
    
    return redirect(f'/product/{product_id}')

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'username' not in session:
        return redirect('/login')
    
    product_id = request.form.get('product_id')
    
    if 'cart' not in session:
        session['cart'] = []
    
    # Cart is stored in session - potential for session manipulation
    cart = session['cart']
    cart.append(product_id)
    session['cart'] = cart
    
    return redirect('/cart')

@app.route('/cart')
def view_cart():
    if 'username' not in session:
        return redirect('/login')
    
    cart_items = []
    total = 0
    
    if 'cart' in session and session['cart']:
        conn = sqlite3.connect('shop.db')
        cursor = conn.cursor()
        
        for product_id in session['cart']:
            cursor.execute("SELECT id, name, price FROM products WHERE id=?", (product_id,))
            product = cursor.fetchone()
            if product:
                cart_items.append(product)
                total += product[2]
        
        conn.close()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Shopping Cart - E-Shop CTF</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                header {
                    background-color: #333;
                    color: white;
                    padding: 10px 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                nav a {
                    color: white;
                    margin-left: 15px;
                    text-decoration: none;
                }
                .container {
                    max-width: 1200px;
                    margin: 20px auto;
                    padding: 20px;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                }
                th, td {
                    padding: 10px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                th {
                    background-color: #f2f2f2;
                }
                .total {
                    text-align: right;
                    margin-top: 20px;
                    font-size: 18px;
                    font-weight: bold;
                }
                .button {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    border: none;
                    font-size: 16px;
                    cursor: pointer;
                    margin-top: 20px;
                }
                .empty-cart {
                    text-align: center;
                    padding: 50px 0;
                }
            </style>
        </head>
        <body>
            <header>
                <h1>E-Shop CTF</h1>
                <div>
                    <span style="color: white; margin-right: 15px;">Welcome, {{ session.username }}!</span>
                    <a href="/">Continue Shopping</a>
                    <a href="/account">My Account</a>
                    <a href="/logout">Logout</a>
                </div>
            </header>
            
            <div class="container">
                <h2>Your Shopping Cart</h2>
                
                {% if cart_items %}
                    <table>
                        <thead>
                            <tr>
                                <th>Product</th>
                                <th>Price</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in cart_items %}
                                <tr>
                                    <td>{{ item[1] }}</td>
                                    <td>${{ "%.2f"|format(item[2]) }}</td>
                                    <td>
                                        <form action="/remove_from_cart" method="post">
                                            <input type="hidden" name="product_id" value="{{ item[0] }}">
                                            <button type="submit" class="button" style="background-color: #e63946;">Remove</button>
                                        </form>
                                    </td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    
                    <div class="total">
                        Total: ${{ "%.2f"|format(total) }}
                    </div>
                    
                    <form action="/checkout" method="post">
                        <button type="submit" class="button">Proceed to Checkout</button>
                    </form>
                {% else %}
                    <div class="empty-cart">
                        <h3>Your cart is empty</h3>
                        <a href="/" class="button">Continue Shopping</a>
                    </div>
                {% endif %}
            </div>
        </body>
        </html>
    ''', cart_items=cart_items, total=total)

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    if 'username' not in session:
        return redirect('/login')
    
    product_id = request.form.get('product_id')
    
    if 'cart' in session and session['cart']:
        cart = session['cart']
        if product_id in cart:
            cart.remove(product_id)
            session['cart'] = cart
    
    return redirect('/cart')

@app.route('/checkout', methods=['POST'])
def checkout():
    if 'username' not in session:
        return redirect('/login')
    
    user_id = session.get('user_id')
    username = session.get('username')
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    try:
        # Get user balance
        cursor.execute("SELECT balance FROM users WHERE id=?", (user_id,))
        user_balance = cursor.fetchone()[0]
        total_cost = 0
        cart_items = []
        
        if 'cart' in session and session['cart']:
            for product_id in session['cart']:
                cursor.execute("SELECT id, name, price, stock FROM products WHERE id=?", (product_id,))
                product = cursor.fetchone()
                if product:
                    cart_items.append(product)
                    total_cost += product[2]
        
        success = False
        error_message = None
        flag_value = None
        hint_value = None
        
        if total_cost <= user_balance:
            # Process the order
            try:
                # Update user balance
                new_balance = user_balance - total_cost
                cursor.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, user_id))
                
                # Create order records and update stock
                for product in cart_items:
                    product_id = product[0]
                    new_stock = product[3] - 1
                    # Update stock
                    cursor.execute("UPDATE products SET stock=? WHERE id=?", (new_stock, product_id))
                    # Create order record
                    cursor.execute("INSERT INTO orders (user_id, product_id, quantity, date, status) VALUES (?, ?, ?, ?, ?)",
                        (user_id, product_id, 1, time.strftime('%Y-%m-%d %H:%M:%S'), 'Processing'))
                
                # Clear the cart
                session['cart'] = []
                conn.commit()
                success = True
                
                # Check if special product was purchased (flag hint or actual flag)
                purchased_flag_hint = False
                purchased_flag = False
                for product in cart_items:
                    if product[0] == 5:  # Flag Hint product
                        purchased_flag_hint = True
                    elif product[0] == 6:  # Professional Drone product
                        purchased_flag = True
                
                # Get flag information if needed
                if purchased_flag:
                    cursor.execute("SELECT flag_value FROM flags WHERE flag_name='main_flag'")
                    flag_result = cursor.fetchone()
                    if flag_result:
                        flag_value = flag_result[0]
                
                if purchased_flag_hint:
                    hint_value = "Try investigating the SQL injection in the login page and the product comment system!"
                    
            except sqlite3.Error as e:
                error_message = f"An error occurred: {str(e)}"
                conn.rollback()
        else:
            error_message = "Insufficient balance to complete the purchase."
    finally:
        conn.close()

        
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Checkout - E-Shop CTF</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                header {
                    background-color: #333;
                    color: white;
                    padding: 10px 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                nav a {
                    color: white;
                    margin-left: 15px;
                    text-decoration: none;
                }
                .container {
                    max-width: 1200px;
                    margin: 20px auto;
                    padding: 20px;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    text-align: center;
                }
                .success {
                    color: #4CAF50;
                    font-size: 24px;
                    margin-bottom: 20px;
                }
                .error {
                    color: #e63946;
                    font-size: 18px;
                    margin-bottom: 20px;
                }
                .button {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    border: none;
                    font-size: 16px;
                    cursor: pointer;
                    margin-top: 20px;
                }
                .flag {
                    margin: 30px auto;
                    padding: 20px;
                    background-color: #f8f9fa;
                    border: 2px dashed #4CAF50;
                    max-width: 80%;
                    font-family: monospace;
                    font-size: 18px;
                }
            </style>
        </head>
        <body>
            <header>
                <h1>E-Shop CTF</h1>
                <div>
                    <span style="color: white; margin-right: 15px;">Welcome, {{ username }}!</span>
                    <a href="/">Continue Shopping</a>
                    <a href="/account">My Account</a>
                    <a href="/logout">Logout</a>
                </div>
            </header>
            
            <div class="container">
                {% if success %}
                    <h2 class="success">Order Completed Successfully!</h2>
                    <p>Thank you for your purchase. Your order is being processed.</p>
                    
                    {% if flag_value %}
                        <div class="flag">
                            <h3>Congratulations! You've found the flag:</h3>
                            <p>{{ flag_value }}</p>
                        </div>
                    {% endif %}
                    
                    {% if hint_value %}
                        <div class="flag">
                            <h3>Flag Hint:</h3>
                            <p>{{ hint_value }}</p>
                        </div>
                    {% endif %}
                    
                    <a href="/" class="button">Continue Shopping</a>
                {% else %}
                    <h2 class="error">Checkout Failed</h2>
                    <p>{{ error_message }}</p>
                    <a href="/cart" class="button">Return to Cart</a>
                {% endif %}
            </div>
        </body>
        </html>
    ''', success=success, error_message=error_message, username=username, flag_value=flag_value, hint_value=hint_value)

@app.route('/account')
def account():
    if 'username' not in session:
        return redirect('/login')
    
    user_id = session.get('user_id')
    username = session.get('username')
    
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    # Get user details
    cursor.execute("SELECT email, role, balance FROM users WHERE id=?", (user_id,))
    user_data = cursor.fetchone()
    
    if not user_data:
        conn.close()
        return "User not found", 404
    
    email, role, balance = user_data
    
    # Get order history
    cursor.execute("""
        SELECT o.id, p.name, o.quantity, o.date, o.status, p.price 
        FROM orders o 
        JOIN products p ON o.product_id = p.id 
        WHERE o.user_id=? 
        ORDER BY o.date DESC
    """, (user_id,))
    orders = cursor.fetchall()
    
    conn.close()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>My Account - E-Shop CTF</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                header {
                    background-color: #333;
                    color: white;
                    padding: 10px 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                nav a {
                    color: white;
                    margin-left: 15px;
                    text-decoration: none;
                }
                .container {
                    max-width: 1200px;
                    margin: 20px auto;
                    padding: 20px;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .account-info {
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 1px solid #eee;
                }
                .account-info div {
                    margin-bottom: 10px;
                }
                .label {
                    font-weight: bold;
                    display: inline-block;
                    width: 120px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }
                th, td {
                    padding: 10px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                th {
                    background-color: #f2f2f2;
                }
                .button {
                    display: inline-block;
                    padding: 8px 16px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    margin-right: 10px;
                }
            </style>
        </head>
        <body>
            <header>
                <h1>E-Shop CTF</h1>
                <div>
                    <span style="color: white; margin-right: 15px;">Welcome, {{ username }}!</span>
                    <a href="/">Continue Shopping</a>
                    <a href="/cart">Cart</a>
                    <a href="/logout">Logout</a>
                </div>
            </header>
            
            <div class="container">
                <h2>My Account</h2>
                
                <div class="account-info">
                    <div><span class="label">Username:</span> {{ username }}</div>
                    <div><span class="label">Email:</span> {{ email }}</div>
                    <div><span class="label">Role:</span> {{ role }}</div>
                    <div><span class="label">Balance:</span> ${{ "%.2f"|format(balance) }}</div>
                </div>
                
                <h3>Order History</h3>
                
                {% if orders %}
                    <table>
                        <thead>
                            <tr>
                                <th>Order ID</th>
                                <th>Product</th>
                                <th>Quantity</th>
                                <th>Price</th>
                                <th>Date</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for order in orders %}
                                <tr>
                                    <td>{{ order[0] }}</td>
                                    <td>{{ order[1] }}</td>
                                    <td>{{ order[2] }}</td>
                                    <td>${{ "%.2f"|format(order[5]) }}</td>
                                    <td>{{ order[3] }}</td>
                                    <td>{{ order[4] }}</td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p>You haven't placed any orders yet.</p>
                {% endif %}
            </div>
        </body>
        </html>
    ''', username=username, email=email, role=role, balance=balance, orders=orders)

@app.route('/logout')
def logout():
    session.clear()
    response = redirect('/')
    response.delete_cookie('auth_token')
    return response

@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    if session.get('role') == 'admin':
        cursor.execute(
            "SELECT id, name, description, price, image_url FROM products WHERE (name LIKE ? OR description LIKE ?)",
            ('%' + query + '%', '%' + query + '%')
        )
    else:
        cursor.execute(
            "SELECT id, name, description, price, image_url FROM products WHERE (name LIKE ? OR description LIKE ?) AND id NOT IN (5,6) AND name NOT IN ('Flag Hint', 'Professional Drone')",
            ('%' + query + '%', '%' + query + '%')
        )
    
    products = cursor.fetchall()
    conn.close()

    # Get user details
    username = session.get('username', None)
    role = session.get('role', 'visitor')
    balance = session.get('balance', 0.0)
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Search Results - E-Shop CTF</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                header {
                    background-color: #333;
                    color: white;
                    padding: 10px 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                nav a {
                    color: white;
                    margin-left: 15px;
                    text-decoration: none;
                }
                .container {
                    max-width: 1200px;
                    margin: 20px auto;
                    padding: 0 20px;
                }
                .products {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                    grid-gap: 20px;
                }
                .product-card {
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    padding: 15px;
                    background-color: white;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .product-card h3 {
                    margin-top: 0;
                }
                .price {
                    font-weight: bold;
                    color: #e63946;
                }
                .search-bar {
                    margin: 20px 0;
                    display: flex;
                }
                .search-bar input {
                    flex-grow: 1;
                    padding: 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px 0 0 4px;
                }
                .search-bar button {
                    padding: 10px 15px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 0 4px 4px 0;
                    cursor: pointer;
                }
                .button {
                    display: inline-block;
                    padding: 8px 16px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    margin-top: 10px;
                }
                .user-info {
                    color: white;
                    display: flex;
                    align-items: center;
                }
                .user-info span {
                    margin-right: 15px;
                }
            </style>
        </head>
        <body>
            <header>
                <h1>E-Shop CTF</h1>
                <div class="user-info">
                    {% if username %}
                        <span>Welcome, {{ username }}!</span>
                        <span>Role: {{ role }}</span>
                        <span>Balance: ${{ "%.2f"|format(balance) }}</span>
                        <a href="/cart">Cart</a>
                        <a href="/account">My Account</a>
                        <a href="/logout">Logout</a>
                    {% else %}
                        <nav>
                            <a href="/login">Login</a>
                            <a href="/register">Register</a>
                        </nav>
                    {% endif %}
                </div>
            </header>
            
            <div class="container">
                <form class="search-bar" action="/search" method="get">
                    <input type="text" name="q" placeholder="Search products..." value="{{ query }}">
                    <button type="submit">Search</button>
                </form>
                
                <h2>Search Results for: {{ query|safe }}</h2>
                
                {% if products %}
                    <div class="products">
                        {% for product in products %}
                            <div class="product-card">
                                <h3>{{ product[1] }}</h3>
                                <p>{{ product[2] }}</p>
                                <p class="price">${{ "%.2f"|format(product[3]) }}</p>
                                <a href="/product/{{ product[0] }}" class="button">View Details</a>
                                <form action="/add_to_cart" method="post" style="display: inline;">
                                    <input type="hidden" name="product_id" value="{{ product[0] }}">
                                    <button type="submit" class="button">Add to Cart</button>
                                </form>
                            </div>
                        {% endfor %}
                    </div>
                {% else %}
                    <p>No products found matching your search criteria.</p>
                {% endif %}
                
                <p><a href="/" class="button" style="margin-top: 20px;">Back to Home</a></p>
            </div>
        </body>
        </html>
    ''', query=query, products=products, username=username, role=role, balance=balance)
# Admin panel route with basic auth but vulnerable
@app.route('/admin')
def admin_panel():
    if 'username' not in session or session.get('role') != 'admin':
        return "Access denied. Admin privileges required.", 403
    
    conn = sqlite3.connect('shop.db')
    cursor = conn.cursor()
    
    # Get all users
    cursor.execute("SELECT id, username, email, role, balance FROM users")
    users = cursor.fetchall()
    
    # Get all orders
    cursor.execute("""
        SELECT o.id, u.username, p.name, o.quantity, o.date, o.status, p.price 
        FROM orders o 
        JOIN users u ON o.user_id = u.id 
        JOIN products p ON o.product_id = p.id 
        ORDER BY o.date DESC
    """)
    orders = cursor.fetchall()
    
    # Get flag
    cursor.execute("SELECT flag_name, flag_value FROM flags")
    flags = cursor.fetchall()
    
    conn.close()
    
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel - E-Shop CTF</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }
                header {
                    background-color: #333;
                    color: white;
                    padding: 10px 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                nav a {
                    color: white;
                    margin-left: 15px;
                    text-decoration: none;
                }
                .container {
                    max-width: 1200px;
                    margin: 20px auto;
                    padding: 20px;
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .section {
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 1px solid #eee;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }
                th, td {
                    padding: 10px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                th {
                    background-color: #f2f2f2;
                }
                .button {
                    display: inline-block;
                    padding: 8px 16px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                    margin-right: 10px;
                }
                .flag-box {
                    background-color: #f8f9fa;
                    border: 2px dashed #e63946;
                    padding: 15px;
                    margin-top: 20px;
                    font-family: monospace;
                }
            </style>
        </head>
        <body>
            <header>
                <h1>E-Shop CTF Admin Panel</h1>
                <div>
                    <span style="color: white; margin-right: 15px;">Logged in as: {{ session.username }} (Admin)</span>
                    <a href="/">Back to Shop</a>
                    <a href="/logout">Logout</a>
                </div>
            </header>
            
            <div class="container">
                <h2>Admin Dashboard</h2>
                
                <div class="section">
                    <h3>CTF Flags</h3>
                    <div class="flag-box">
                        {% for flag in flags %}
                            <div>
                                <strong>{{ flag[0] }}:</strong> {{ flag[1] }}
                            </div>
                        {% endfor %}
                    </div>
                </div>
                
                <div class="section">
                    <h3>User Management</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Balance</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for user in users %}
                                <tr>
                                    <td>{{ user[0] }}</td>
                                    <td>{{ user[1] }}</td>
                                    <td>{{ user[2] }}</td>
                                    <td>{{ user[3] }}</td>
                                    <td>${{ "%.2f"|format(user[4]) }}</td>
                                    <td>
                                        <a href="#" class="button">Edit</a>
                                        <a href="#" class="button" style="background-color: #e63946;">Delete</a>
                                    </td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                
                <div class="section">
                    <h3>Order Management</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Order ID</th>
                                <th>User</th>
                                <th>Product</th>
                                <th>Quantity</th>
                                <th>Price</th>
                                <th>Date</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for order in orders %}
                                <tr>
                                    <td>{{ order[0] }}</td>
                                    <td>{{ order[1] }}</td>
                                    <td>{{ order[2] }}</td>
                                    <td>{{ order[3] }}</td>
                                    <td>${{ "%.2f"|format(order[6]) }}</td>
                                    <td>{{ order[4] }}</td>
                                    <td>{{ order[5] }}</td>
                                    <td>
                                        <a href="#" class="button">Update</a>
                                    </td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </body>
        </html>
    ''', users=users, orders=orders, flags=flags)

# Run the application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=1234)

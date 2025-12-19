import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysupersecretshop'
basedir = os.path.abspath(os.path.dirname(__file__))

# Database & Upload Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'shop.dp')
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MASTER SECRET CONFIG (INDEPENDENT ADMIN LOCK) ---
ADMIN_SECRET_PASS = "sahal password13221"

# --- MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    orders = db.relationship('Order', backref='customer', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(100))
    stock = db.Column(db.Integer, default=10)
    category = db.Column(db.String(50))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_details = db.Column(db.Text) # Stores Name, Phone, Address, Payment
    total_price = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ADMIN ROUTES (MODERNIZED) ---
ADMIN_SECRET_PASS = "razi1321"

@app.route('/admin_lock', methods=['GET', 'POST'])
def admin_lock():
    if request.method == 'POST':
        if request.form.get('admin_pass') == ADMIN_SECRET_PASS:
            session['admin_verified'] = True
            return redirect(url_for('admin'))
        flash("Invalid Master Key!")
    return render_template('admin_lock.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_verified', None)
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # 1. Security Check
    if not session.get('admin_verified'):
        return redirect(url_for('admin_lock'))

    # 2. Handle Product Adding (POST)
    if request.method == 'POST':
        f = request.files.get('image')
        if f:
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))
            p = Product(
                name=request.form.get('name'), 
                price=request.form.get('price'), 
                stock=request.form.get('stock'), 
                category=request.form.get('category'), 
                image=f.filename
            )
            db.session.add(p)
            db.session.commit()
            flash("Product added successfully!")
            return redirect(url_for('admin'))
    
    # 3. Load Data for the Dashboard
    products = Product.query.all()
    # We sort orders by ID descending so newest orders/returns appear at the top
    orders = Order.query.order_by(Order.id.desc()).all() 
    
    return render_template('admin.html', products=products, orders=orders)

# Route to delete products
@app.route('/delete/<int:id>')
def delete_product(id):
    if session.get('admin_verified'):
        p = Product.query.get(id)
        if p:
            db.session.delete(p)
            db.session.commit()
    return redirect(url_for('admin'))

# Route to delete/clear order records
@app.route('/delete_order/<int:id>')
def delete_order(id):
    if session.get('admin_verified'):
        order = Order.query.get(id)
        if order:
            db.session.delete(order)
            db.session.commit()
            flash("Order record cleared.")
    return redirect(url_for('admin'))

# --- USER SHOP ROUTES ---

@app.route('/')
def index():
    q = request.args.get('q')
    query = Product.query
    if q: query = query.filter(Product.name.contains(q))
    return render_template('index.html', products=query.all())

@app.route('/buy/<int:id>')
def buy_now(id):
    if not current_user.is_authenticated:
        flash("Please login or signup to buy!")
        return redirect(url_for('signup'))
    session['cart'] = [id] # Direct buy clears cart and adds only this item
    return redirect(url_for('checkout'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    items = [Product.query.get(i) for i in cart_ids if Product.query.get(i)]
    total = sum(i.price for i in items)

    if request.method == 'POST':
        addr = request.form.get('address')
        pay_id = request.form.get('pay_number')
        method = request.form.get('payment_method')
        
        product_list = ", ".join([i.name for i in items])
        summary = f"ITEMS: {product_list} | CONTACT: {pay_id} | ADDR: {addr}"

        # CRITICAL: We must pass current_user.id here
        new_order = Order(
            product_details=summary, 
            total_price=total, 
            user_id=current_user.id  # THIS LINKS THE ORDER TO THE LOGGED IN USER
        )
        
        db.session.add(new_order)
        db.session.commit()
        
        session.pop('cart', None)
        flash("Order placed!")
        return redirect(url_for('profile')) # Go to My Orders page

    return render_template('checkout.html', items=items, total=total)
# --- AUTH ROUTES ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        if User.query.filter_by(username=u).first():
            flash("Username already taken!")
            return redirect(url_for('signup'))
        new_user = User(username=u, password=generate_password_hash(p))
        db.session.add(new_user); db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash("Invalid Credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    # Fetch orders that belong ONLY to the logged-in user
    my_orders = Order.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', orders=my_orders)

@app.route('/cancel_order/<int:id>')
@login_required
def cancel_order(id):
    order = Order.query.get(id)
    # Check if order exists and belongs to the current user
    if order and order.user_id == current_user.id:
        db.session.delete(order)
        db.session.commit()
        flash("Order cancelled successfully.")
    return redirect(url_for('profile'))

@app.route('/return_order/<int:id>')
@login_required
def return_order(id):
    order = Order.query.get(id)
    if order and order.user_id == current_user.id:
        # You can update the details to notify the admin
        order.product_details = "[RETURN REQUESTED] " + order.product_details
        db.session.commit()
        flash("Return request submitted.")
    return redirect(url_for('profile'))
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']): 
        os.makedirs(app.config['UPLOAD_FOLDER'])
    with app.app_context(): 
        db.create_all()
    app.run(debug=True)
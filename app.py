from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import csv
from io import StringIO

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-default-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    monthly_income = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expenses = db.relationship('Expense', backref='user', lazy='dynamic')
    additional_incomes = db.relationship('AdditionalIncome', backref='user', lazy='dynamic')

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

class AdditionalIncome(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    source = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    income_type = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

# --- Authentication Decorator ---
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/')
@login_required
def home():
    user = User.query.get(session['user_id'])
    # MODIFIED: Changed filter from 'first day of month' to 'last 30 days'
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    # Expenses in the last 30 days
    recent_period_expenses = user.expenses.filter(Expense.date >= thirty_days_ago).all()
    total_expenses = sum(exp.amount for exp in recent_period_expenses)
    
    # Additional income in the last 30 days
    recent_period_additional_income = user.additional_incomes.filter(AdditionalIncome.date >= thirty_days_ago).all()
    additional_income = sum(inc.amount for inc in recent_period_additional_income)
    
    # NOTE: The base income is monthly, so we divide by 30 to get a daily rate and multiply by 30
    # for this period. This approach normalizes the income over the 30-day view.
    total_income = user.monthly_income + additional_income
    remaining = total_income - total_expenses
    
    # Budget calculations (based on full monthly income)
    needs_budget = user.monthly_income * 0.5
    wants_budget = user.monthly_income * 0.3
    savings_budget = user.monthly_income * 0.2
    
    recent_expenses = user.expenses.order_by(Expense.date.desc()).limit(5).all()

    # Prepare chart data
    chart_data = prepare_chart_data(user)

    return render_template('index.html',
                         user=user,
                         salary=total_income,
                         expenses=recent_expenses,
                         total_expenses=total_expenses,
                         remaining=remaining,
                         additional_income=additional_income,
                         needs_budget=needs_budget,
                         wants_budget=wants_budget,
                         savings_budget=savings_budget,
                         chart_data=chart_data)

def prepare_chart_data(user):
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    # MODIFIED: Category data for pie chart (last 30 days)
    category_totals = {}
    for expense in user.expenses.filter(Expense.date >= thirty_days_ago).all():
        category_totals[expense.category] = category_totals.get(expense.category, 0) + expense.amount
    
    categories = {
        'labels': list(category_totals.keys()),
        'data': list(category_totals.values())
    }
    
    # Time series data for line chart (last 30 days - no change needed here)
    daily_totals = {}
    for i in range(30):
        date = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
        daily_totals[date] = 0
    
    for expense in user.expenses.filter(Expense.date >= thirty_days_ago).all():
        date_str = expense.date.strftime('%Y-%m-%d')
        if date_str in daily_totals:
            daily_totals[date_str] += expense.amount
    
    sorted_dates = sorted(daily_totals.keys())
    time_series = {
        'labels': [datetime.strptime(date, '%Y-%m-%d').strftime('%m/%d') for date in sorted_dates],
        'data': [daily_totals[date] for date in sorted_dates]
    }
    
    # MODIFIED: Income vs Expense data (last 30 days)
    expenses_last_30_days = sum(exp.amount for exp in user.expenses.filter(Expense.date >= thirty_days_ago).all())
    additional_income_last_30_days = sum(inc.amount for inc in user.additional_incomes.filter(AdditionalIncome.date >= thirty_days_ago).all())
    total_income_period = user.monthly_income + additional_income_last_30_days
    
    income_expense = {
        'income': total_income_period,
        'expenses': expenses_last_30_days
    }
    
    return {
        'categories': categories,
        'time_series': time_series,
        'income_expense': income_expense
    }

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        monthly_income = float(request.form.get('monthly_income', 0))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')
        
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            monthly_income=monthly_income
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    user_id = session['user_id']
    try:
        amount = float(request.form['amount'])
        name = request.form['name']
        category = request.form['category']
        notes = request.form.get('notes', '')

        if not name or not category:
            flash('Name and category are required.', 'error')
            return redirect(url_for('home'))

        expense = Expense(user_id=user_id, name=name, amount=amount, category=category, notes=notes)
        db.session.add(expense)
        db.session.commit()
        flash('Expense added successfully!', 'success')
    except (ValueError, KeyError):
        flash('Invalid data submitted. Please try again.', 'error')
    
    return redirect(url_for('home'))

@app.route('/add_income', methods=['POST'])
@login_required
def add_income():
    user_id = session['user_id']
    try:
        amount = float(request.form['amount'])
        source = request.form['source']
        income_type = request.form['income_type']
        notes = request.form.get('notes', '')

        if not source or not income_type:
            flash('Source and income type are required.', 'error')
            return redirect(url_for('home'))

        additional_income = AdditionalIncome(
            user_id=user_id, 
            source=source, 
            amount=amount, 
            income_type=income_type, 
            notes=notes
        )
        db.session.add(additional_income)
        db.session.commit()
        flash('Additional income recorded successfully!', 'success')
    except (ValueError, KeyError):
        flash('Invalid data submitted. Please try again.', 'error')
    
    return redirect(url_for('home'))

@app.route('/history')
@login_required
def history():
    user = User.query.get(session['user_id'])
    category_filter = request.args.get('category', '')
    date_from_str = request.args.get('date_from', '')
    date_to_str = request.args.get('date_to', '')
    
    query = Expense.query.filter_by(user_id=user.id)
    
    if category_filter:
        query = query.filter_by(category=category_filter)
    
    try:
        if date_from_str:
            date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
            query = query.filter(Expense.date >= date_from)
        if date_to_str:
            date_to = datetime.strptime(date_to_str, '%Y-%m-%d')
            query = query.filter(Expense.date < date_to + timedelta(days=1))
    except ValueError:
        flash('Invalid date format. Please use YYYY-MM-DD.', 'error')

    expenses = query.order_by(Expense.date.desc()).all()
    
    categories = [cat[0] for cat in db.session.query(Expense.category).filter_by(user_id=user.id).distinct().all()]
    
    return render_template('history.html', 
                         user=user,
                         expenses=expenses, 
                         categories=categories,
                         filters={
                             'category': category_filter,
                             'date_from': date_from_str,
                             'date_to': date_to_str
                         })

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        try:
            income = float(request.form.get('monthly_income', user.monthly_income))
            user.monthly_income = income
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except (ValueError, TypeError):
            flash('Invalid income amount entered.', 'error')
        return redirect(url_for('profile'))
    
    # Calculate stats
    total_expenses = sum(expense.amount for expense in user.expenses.all())
    
    days_since_creation = (datetime.utcnow() - user.created_at).days
    if days_since_creation > 0:
        months_since_creation = max(1, days_since_creation / 30.44)
        avg_monthly = total_expenses / months_since_creation
    else:
        avg_monthly = 0

    return render_template(
        'profile.html', 
        user=user,
        total_expenses=total_expenses,
        avg_monthly=avg_monthly
    )

@app.route('/export_csv')
@login_required
def export_csv():
    user = User.query.get(session['user_id'])
    expenses = user.expenses.order_by(Expense.date.desc()).all()
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Name', 'Amount', 'Category', 'Notes'])
    
    for expense in expenses:
        writer.writerow([
            expense.date.strftime('%Y-%m-%d'), 
            expense.name, 
            expense.amount, 
            expense.category, 
            expense.notes or ''
        ])
    
    output.seek(0)
    
    return output.getvalue(), 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment;filename=expenses.csv'
    }

# --- Initialize database ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
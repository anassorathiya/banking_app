"""
Enhanced Banking Application with OTP-based 2FA
Complete banking system with advanced features: Loans, Investments, Bill Payments, Analytics
"""

import os
import re
import uuid
import random
import hashlib
import secrets
import smtplib
import datetime
import json
import calendar
from decimal import Decimal, ROUND_HALF_UP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict
from bson import ObjectId
from bson.json_util import dumps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
from flask_session import Session
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, ConnectionFailure
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging
from io import BytesIO
import qrcode
import base64
from datetime import timedelta

# ==================== Configuration ====================

class Config:
    """Application configuration"""
    SECRET_KEY = secrets.token_hex(32)
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    
    # MongoDB Configuration
    MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
    DATABASE_NAME = 'banking_app'
    
    # Email Configuration (for OTP)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('EMAIL_USER', 'your_email@gmail.com')
    MAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'your_app_password')
    
    # OTP Configuration
    OTP_EXPIRY_MINUTES = 5
    OTP_LENGTH = 6
    
    # Security
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME_MINUTES = 30
    PASSWORD_MIN_LENGTH = 8
    
    # Transaction Limits
    DAILY_TRANSACTION_LIMIT = 100000
    MAX_TRANSACTION_AMOUNT = 50000
    
    # Interest Rates
    SAVINGS_INTEREST_RATE = 3.5
    FIXED_DEPOSIT_RATES = {
        '6_months': 5.5,
        '1_year': 6.0,
        '2_years': 6.5,
        '5_years': 7.0
    }
    
    # Loan Rates
    PERSONAL_LOAN_RATE = 10.5
    HOME_LOAN_RATE = 7.5
    CAR_LOAN_RATE = 8.5
    EDUCATION_LOAN_RATE = 9.0
    
    # Rewards
    REWARDS_MULTIPLIER = 1
    
    # Bill Categories
    BILL_CATEGORIES = ['Electricity', 'Water', 'Internet', 'Mobile', 'Credit Card', 'Gas', 'Insurance']

# ==================== Database Setup ====================

class Database:
    """Database operations handler"""
    
    def __init__(self):
        try:
            client = MongoClient(Config.MONGODB_URI)
            self.db = client[Config.DATABASE_NAME]
            
            # Create indexes
            self.db.users.create_index("email", unique=True)
            self.db.users.create_index("account_number", unique=True)
            self.db.users.create_index("phone_number", unique=True)
            self.db.otp_codes.create_index("created_at", expireAfterSeconds=300)
            self.db.transactions.create_index("account_number")
            self.db.transactions.create_index([("timestamp", -1)])
            self.db.failed_logins.create_index("timestamp", expireAfterSeconds=1800)
            self.db.loans.create_index("account_number")
            self.db.investments.create_index("account_number")
            self.db.bills.create_index("account_number")
            self.db.rewards.create_index("account_number", unique=True)
            self.db.biometric_data.create_index("email", unique=True)
            self.db.transactions.create_index([("timestamp", -1)])
            
            print("✓ MongoDB connected successfully")
        except ConnectionFailure as e:
            print(f"✗ MongoDB connection failed: {e}")
            exit(1)
    
    def get_collection(self, name):
        return self.db[name]

# ==================== Models ====================

@dataclass
class User:
    """User model"""
    email: str
    password_hash: str
    full_name: str
    account_number: str
    phone_number: str
    balance: float = 0.0
    is_verified: bool = False
    is_active: bool = True
    created_at: datetime.datetime = None
    last_login: datetime.datetime = None
    two_factor_enabled: bool = True
    biometric_enabled: bool = False
    profile_pic: str = None
    address: str = None
    date_of_birth: str = None
    occupation: str = None
    annual_income: float = 0.0
    credit_score: int = 750
    kyc_status: str = 'pending'
    preferred_language: str = 'en'
    notification_preferences: Dict = None
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.datetime.now()
        if not self.account_number:
            self.account_number = self.generate_account_number()
        if not self.notification_preferences:
            self.notification_preferences = {
                'email': True,
                'sms': False,
                'push': True
            }
    
    @staticmethod
    def generate_account_number():
        return str(random.randint(100000000000, 999999999999))
    
    def to_dict(self):
        data = asdict(self)
        data['_id'] = self.email
        return data

@dataclass
class OTPCode:
    """OTP model"""
    email: str
    otp_code: str
    purpose: str
    created_at: datetime.datetime = None
    expires_at: datetime.datetime = None
    is_used: bool = False
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.datetime.now()
        if not self.expires_at:
            self.expires_at = self.created_at + datetime.timedelta(minutes=Config.OTP_EXPIRY_MINUTES)
        if not self.otp_code:
            self.otp_code = self.generate_otp()
    
    @staticmethod
    def generate_otp():
        return ''.join([str(random.randint(0, 9)) for _ in range(Config.OTP_LENGTH)])
    
    def to_dict(self):
        return asdict(self)

@dataclass
class Transaction:
    """Transaction model"""
    transaction_id: str
    account_number: str
    transaction_type: str
    amount: float
    description: str
    timestamp: datetime.datetime = None
    status: str = 'completed'
    recipient_account: str = None
    balance_after: float = None
    category: str = None
    location: str = None
    device_info: str = None
    points_earned: int = 0
    
    def __post_init__(self):
        if not self.transaction_id:
            self.transaction_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.datetime.now()
        if not self.category:
            self.category = self.categorize_transaction()
    
    def categorize_transaction(self):
        categories = {
            'food': ['restaurant', 'cafe', 'food', 'dining', 'pizza'],
            'shopping': ['amazon', 'flipkart', 'mall', 'store', 'shopping'],
            'transport': ['uber', 'ola', 'taxi', 'fuel', 'petrol', 'train'],
            'entertainment': ['netflix', 'prime', 'movie', 'cinema', 'spotify'],
            'bills': ['electricity', 'water', 'gas', 'internet', 'mobile'],
            'healthcare': ['hospital', 'clinic', 'pharmacy', 'doctor'],
            'education': ['school', 'college', 'course', 'tuition']
        }
        
        desc_lower = self.description.lower()
        for category, keywords in categories.items():
            if any(keyword in desc_lower for keyword in keywords):
                return category
        return 'other'
    
    def to_dict(self):
        return asdict(self)

@dataclass
class Loan:
    """Loan model"""
    loan_id: str
    account_number: str
    loan_type: str
    principal_amount: float
    interest_rate: float
    tenure_months: int
    monthly_emi: float
    total_interest: float
    total_payable: float
    amount_paid: float = 0.0
    remaining_balance: float = None
    start_date: datetime.datetime = None
    next_due_date: datetime.datetime = None
    status: str = 'active'
    approved_date: datetime.datetime = None
    documents: List[str] = None
    
    def __post_init__(self):
        if not self.loan_id:
            self.loan_id = str(uuid.uuid4())
        if not self.start_date:
            self.start_date = datetime.datetime.now()
        if not self.remaining_balance:
            self.remaining_balance = self.principal_amount
        if not self.next_due_date:
            self.next_due_date = self.start_date + datetime.timedelta(days=30)
        if not self.documents:
            self.documents = []
        self.calculate_emi()
    
    def calculate_emi(self):
        monthly_rate = (self.interest_rate / 100) / 12
        if monthly_rate == 0:
            self.monthly_emi = self.principal_amount / self.tenure_months
        else:
            self.monthly_emi = self.principal_amount * monthly_rate * (1 + monthly_rate) ** self.tenure_months / \
                              ((1 + monthly_rate) ** self.tenure_months - 1)
        self.total_interest = (self.monthly_emi * self.tenure_months) - self.principal_amount
        self.total_payable = self.principal_amount + self.total_interest
    
    def to_dict(self):
        return asdict(self)

@dataclass
class Investment:
    """Investment model"""
    investment_id: str
    account_number: str
    investment_type: str
    amount: float
    tenure_months: int
    interest_rate: float
    maturity_amount: float
    maturity_date: datetime.datetime
    start_date: datetime.datetime = None
    status: str = 'active'
    current_value: float = None
    
    def __post_init__(self):
        if not self.investment_id:
            self.investment_id = str(uuid.uuid4())
        if not self.start_date:
            self.start_date = datetime.datetime.now()
        if not self.current_value:
            self.current_value = self.amount
        self.calculate_maturity()
    
    def calculate_maturity(self):
        if self.investment_type == 'fixed_deposit':
            rate = self.interest_rate / 100
            self.maturity_amount = self.amount * (1 + rate) ** (self.tenure_months / 12)
        else:
            self.maturity_amount = self.amount
    
    def to_dict(self):
        return asdict(self)

@dataclass
class Bill:
    """Bill model"""
    bill_id: str
    account_number: str
    bill_type: str
    biller_name: str
    biller_account: str
    amount: float
    due_date: datetime.datetime
    paid_date: datetime.datetime = None
    status: str = 'pending'
    late_fee: float = 0.0
    
    def __post_init__(self):
        if not self.bill_id:
            self.bill_id = str(uuid.uuid4())
        if self.due_date < datetime.datetime.now() and self.status == 'pending':
            self.status = 'overdue'
            self.late_fee = self.amount * 0.02
    
    def to_dict(self):
        return asdict(self)

@dataclass
class Reward:
    """Rewards model"""
    account_number: str
    points: int = 0
    tier: str = 'bronze'
    points_earned_this_month: int = 0
    last_updated: datetime.datetime = None
    
    def __post_init__(self):
        if not self.last_updated:
            self.last_updated = datetime.datetime.now()
        self.update_tier()
    
    def update_tier(self):
        if self.points >= 50000:
            self.tier = 'platinum'
        elif self.points >= 25000:
            self.tier = 'gold'
        elif self.points >= 10000:
            self.tier = 'silver'
        else:
            self.tier = 'bronze'
    
    def to_dict(self):
        return asdict(self)

@dataclass
class Notification:
    account_number: str
    title: str
    message: str
    type: str
    notification_id: str = None
    timestamp: datetime.datetime = None
    is_read: bool = False

    def __post_init__(self):
        if not self.notification_id:
            self.notification_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.datetime.now()

    def to_dict(self):
        return asdict(self)

# ==================== Flask Application ====================

app = Flask(__name__)
app.config.from_object(Config)
app.permanent_session_lifetime = Config.PERMANENT_SESSION_LIFETIME
Session(app)

# Initialize database
db = Database()
users_collection = db.get_collection('users')
otp_collection = db.get_collection('otp_codes')
transactions_collection = db.get_collection('transactions')
failed_logins_collection = db.get_collection('failed_logins')
loans_collection = db.get_collection('loans')
investments_collection = db.get_collection('investments')
bills_collection = db.get_collection('bills')
rewards_collection = db.get_collection('rewards')
biometric_collection = db.get_collection('biometric_data')
notifications_collection = db.get_collection('notifications')

# ==================== Helper Functions ====================

def format_currency(amount: float) -> str:
    return f"${amount:,.2f}"

def format_percentage(rate: float) -> str:
    return f"{rate:.1f}%"

def calculate_credit_score(user_data: Dict) -> int:
    score = 750
    
    account_age = (datetime.datetime.now() - user_data['created_at']).days
    if account_age > 365 * 5:
        score += 50
    elif account_age > 365 * 2:
        score += 25
    elif account_age > 365:
        score += 10
    
    transactions = list(transactions_collection.find({'account_number': user_data['account_number']}))
    if len(transactions) > 100:
        score += 30
    elif len(transactions) > 50:
        score += 20
    elif len(transactions) > 20:
        score += 10
    
    if user_data['balance'] > 10000:
        score += 20
    elif user_data['balance'] > 5000:
        score += 10
    
    loans = list(loans_collection.find({'account_number': user_data['account_number'], 'status': 'active'}))
    for loan in loans:
        if loan['amount_paid'] > 0:
            score += 15
    
    return min(850, score)

def calculate_interest(principal: float, rate: float, days: int) -> float:
    return (principal * rate * days) / (365 * 100)

def generate_qr(data: str) -> str:
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

def add_notification(account_number: str, title: str, message: str, type: str = 'info'):
    notification = Notification(
        account_number=account_number,
        title=title,
        message=message,
        type=type
    )
    notifications_collection.insert_one(notification.to_dict())

def calculate_rewards(account_number: str, amount: float):
    points = int(amount / 100) * Config.REWARDS_MULTIPLIER
    if points > 0:
        reward = rewards_collection.find_one({'account_number': account_number})
        if reward:
            rewards_collection.update_one(
                {'account_number': account_number},
                {'$inc': {'points': points, 'points_earned_this_month': points},
                 '$set': {'last_updated': datetime.datetime.now()}}
            )
        else:
            reward_obj = Reward(account_number=account_number, points=points, points_earned_this_month=points)
            rewards_collection.insert_one(reward_obj.to_dict())
        
        update_reward_tier(account_number)

def update_reward_tier(account_number: str):
    reward = rewards_collection.find_one({'account_number': account_number})
    if reward:
        points = reward['points']
        if points >= 50000 and reward['tier'] != 'platinum':
            rewards_collection.update_one(
                {'account_number': account_number},
                {'$set': {'tier': 'platinum'}}
            )
            add_notification(account_number, "Congratulations!", 
                           "You've reached Platinum tier! Enjoy exclusive benefits!", "success")
        elif points >= 25000 and reward['tier'] != 'gold':
            rewards_collection.update_one(
                {'account_number': account_number},
                {'$set': {'tier': 'gold'}}
            )
            add_notification(account_number, "Tier Upgrade!", 
                           "Congratulations! You're now a Gold member!", "success")
        elif points >= 10000 and reward['tier'] != 'silver':
            rewards_collection.update_one(
                {'account_number': account_number},
                {'$set': {'tier': 'silver'}}
            )
            add_notification(account_number, "Tier Upgrade!", 
                           "Congratulations! You're now a Silver member!", "success")

def get_tier_benefits(tier: str) -> Dict:
    benefits = {
        'bronze': {
            'cashback_rate': 0.5,
            'atm_withdrawal_limit': 500,
            'free_transactions': 10,
            'priority_support': False
        },
        'silver': {
            'cashback_rate': 1.0,
            'atm_withdrawal_limit': 1000,
            'free_transactions': 20,
            'priority_support': False
        },
        'gold': {
            'cashback_rate': 1.5,
            'atm_withdrawal_limit': 1500,
            'free_transactions': 50,
            'priority_support': True
        },
        'platinum': {
            'cashback_rate': 2.0,
            'atm_withdrawal_limit': 2500,
            'free_transactions': 100,
            'priority_support': True
        }
    }
    return benefits.get(tier, benefits['bronze'])

def get_financial_insights(account_number: str) -> Dict:
    transactions = list(transactions_collection.find(
        {'account_number': account_number}
    ).sort('timestamp', -1).limit(100))
    
    if not transactions:
        return {}
    
    category_spending = defaultdict(float)
    for tx in transactions:
        if tx['transaction_type'] in ['debit', 'transfer'] and tx['amount'] > 0:
            category = tx.get('category', 'other')
            category_spending[category] += tx['amount']
    
    monthly_spending = defaultdict(float)
    for tx in transactions:
        month = tx['timestamp'].strftime('%Y-%m')
        if tx['transaction_type'] in ['debit', 'transfer']:
            monthly_spending[month] += tx['amount']
    
    avg_monthly = sum(monthly_spending.values()) / max(len(monthly_spending), 1)
    
    insights = {
        'top_category': max(category_spending.items(), key=lambda x: x[1])[0] if category_spending else None,
        'top_category_amount': max(category_spending.values()) if category_spending else 0,
        'avg_monthly_spending': avg_monthly,
        'savings_rate': 0,
        'recommendations': []
    }
    
    if insights['top_category'] == 'food' and insights['top_category_amount'] > 500:
        insights['recommendations'].append("Consider cooking at home more often to save on food expenses")
    
    if insights['avg_monthly_spending'] > 2000:
        insights['recommendations'].append("You're spending above average. Consider creating a budget")
    
    return insights

# ==================== Authentication Decorators ====================

@app.context_processor
def inject_functions():
    return dict(format_currency=format_currency)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def two_factor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('two_factor_verified', False):
            flash('Please complete two-factor authentication', 'warning')
            return redirect(url_for('verify_otp_page'))
        return f(*args, **kwargs)
    return decorated_function

def biometric_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = users_collection.find_one({'email': session.get('user_email')})
        if user and user.get('biometric_enabled', False) and not session.get('biometric_verified', False):
            flash('Biometric verification required', 'warning')
            return redirect(url_for('biometric_verify'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== Email Service ====================

class EmailService:
    @staticmethod
    def send_otp_email(email: str, otp: str, purpose: str) -> bool:
        try:
            msg = MIMEMultipart()
            msg['From'] = Config.MAIL_USERNAME
            msg['To'] = email
            msg['Subject'] = f"Your OTP for {purpose.title()} - SecureBank"
            
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #004d40, #00695c); color: white; 
                              padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                    .content {{ background: #f9f9f9; padding: 30px; }}
                    .otp-code {{ font-size: 36px; font-weight: bold; color: #004d40; text-align: center; 
                                padding: 20px; letter-spacing: 8px; background: white; 
                                margin: 20px 0; border-radius: 10px; border: 2px dashed #004d40; }}
                    .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
                    .warning {{ color: #f44336; font-size: 13px; text-align: center; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>🏦 SecureBank</h2>
                        <p>Your Trusted Banking Partner</p>
                    </div>
                    <div class="content">
                        <p>Dear Customer,</p>
                        <p>Your One-Time Password (OTP) for <strong>{purpose}</strong> is:</p>
                        <div class="otp-code">{otp}</div>
                        <p>This OTP is valid for <strong>{Config.OTP_EXPIRY_MINUTES} minutes</strong>.</p>
                        <p>For security reasons, never share this OTP with anyone, not even bank representatives.</p>
                        <div class="warning">
                            ⚠️ If you didn't request this OTP, please contact support immediately at support@securebank.com
                        </div>
                    </div>
                    <div class="footer">
                        <p>This is an automated message, please do not reply.</p>
                        <p>&copy; 2024 SecureBank. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            server = smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT)
            server.starttls()
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.send_message(msg)
            server.quit()
            
            return True
        except Exception as e:
            print(f"Email error: {e}")
            return False

# ==================== Authentication Functions ====================

def validate_password(password: str) -> Tuple[bool, str]:
    if len(password) < Config.PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {Config.PASSWORD_MIN_LENGTH} characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_phone(phone: str) -> bool:
    pattern = r'^[0-9]{10}$'
    return bool(re.match(pattern, phone))

def is_account_locked(email: str) -> bool:
    lockout_time = datetime.datetime.now() - datetime.timedelta(minutes=Config.LOCKOUT_TIME_MINUTES)
    failed_attempts = failed_logins_collection.count_documents({
        'email': email,
        'timestamp': {'$gt': lockout_time}
    })
    return failed_attempts >= Config.MAX_LOGIN_ATTEMPTS

def record_failed_login(email: str):
    failed_logins_collection.insert_one({
        'email': email,
        'timestamp': datetime.datetime.now(),
        'ip_address': request.remote_addr
    })

def clear_failed_logins(email: str):
    failed_logins_collection.delete_many({'email': email})

def generate_otp(email: str, purpose: str) -> Optional[str]:
    existing_otp = otp_collection.find_one({
        'email': email,
        'purpose': purpose,
        'is_used': False,
        'expires_at': {'$gt': datetime.datetime.now()}
    })

    if existing_otp:
        otp_code = existing_otp['otp_code']
    else:
        # ✅ Generate OTP manually
        otp_code = str(random.randint(100000, 999999))

        # ✅ FIX: pass otp_code here
        otp = OTPCode(
            email=email,
            purpose=purpose,
            otp_code=otp_code
        )

        otp_collection.insert_one(otp.to_dict())

    # -------- SEND EMAIL -------- #
    try:
        if EmailService.send_otp_email(email, otp_code, purpose):
            return otp_code
        else:
            print("Email sending failed")
            return None
    except Exception as e:
        print("Email Error:", e)
        return None

def verify_otp(email: str, otp_code: str, purpose: str) -> bool:
    otp_record = otp_collection.find_one({
        'email': email,
        'otp_code': otp_code,
        'purpose': purpose,
        'is_used': False,
        'expires_at': {'$gt': datetime.datetime.now()}
    })
    
    if otp_record:
        otp_collection.update_one(
            {'_id': otp_record['_id']},
            {'$set': {'is_used': True}}
        )
        return True
    return False


def process_transaction(transaction_data):
    try:
        sender_email = transaction_data['sender_email']
        recipient_account = transaction_data['recipient_account']
        amount = transaction_data['amount']
        description = transaction_data['description']
        
        sender = users_collection.find_one({'email': sender_email})
        if not sender:
            return False
        
        if sender['balance'] < amount:
            return False
        
        recipient = users_collection.find_one({'account_number': recipient_account})
        if not recipient:
            return False
        
        reward = rewards_collection.find_one({'account_number': sender['account_number']})
        tier = reward['tier'] if reward else 'bronze'
        benefits = get_tier_benefits(tier)
        cashback = amount * (benefits['cashback_rate'] / 100)
        
        new_sender_balance = sender['balance'] - amount + cashback
        new_recipient_balance = recipient['balance'] + amount
        
        users_collection.update_one(
            {'email': sender_email},
            {'$set': {'balance': new_sender_balance}}
        )
        users_collection.update_one(
            {'account_number': recipient_account},
            {'$set': {'balance': new_recipient_balance}}
        )
        
        points_earned = int(amount / 100) * Config.REWARDS_MULTIPLIER
        calculate_rewards(sender['account_number'], amount)
        
        sender_transaction = Transaction(
            account_number=sender['account_number'],
            transaction_type='debit',
            amount=amount,
            description=f"Transfer to {recipient_account}: {description}",
            recipient_account=recipient_account,
            balance_after=new_sender_balance,
            points_earned=points_earned
        )
        
        recipient_transaction = Transaction(
            account_number=recipient_account,
            transaction_type='credit',
            amount=amount,
            description=f"Transfer from {sender['account_number']}: {description}",
            recipient_account=sender['account_number'],
            balance_after=new_recipient_balance
        )
        
        transactions_collection.insert_one(sender_transaction.to_dict())
        transactions_collection.insert_one(recipient_transaction.to_dict())
        
        if cashback > 0:
            cashback_transaction = Transaction(
                account_number=sender['account_number'],
                transaction_type='credit',
                amount=cashback,
                description=f"Cashback earned ({tier} tier)",
                balance_after=new_sender_balance
            )
            transactions_collection.insert_one(cashback_transaction.to_dict())
        
        add_notification(sender['account_number'], "Transfer Completed", 
                        f"${amount:,.2f} transferred to {recipient_account}", "success")
        add_notification(recipient['account_number'], "Money Received", 
                        f"${amount:,.2f} received from {sender['account_number']}", "success")
        
        return True
    except Exception as e:
        print(f"Transaction error: {e}")
        return False

# ==================== Routes ====================

@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # -------- GET FORM DATA -------- #
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            full_name = request.form.get('full_name', '').strip()
            phone_number = request.form.get('phone_number', '').strip()
            date_of_birth = request.form.get('date_of_birth', '')
            address = request.form.get('address', '')
            occupation = request.form.get('occupation', '')

            # -------- SAFE ANNUAL INCOME -------- #
            annual_income_raw = request.form.get('annual_income', '').strip()
            try:
                annual_income = float(annual_income_raw) if annual_income_raw else 0
            except ValueError:
                flash('Invalid annual income value', 'danger')
                return render_template('register.html')

            # -------- REQUIRED FIELDS -------- #
            if not all([email, password, confirm_password, full_name, phone_number]):
                flash('Please fill all required fields', 'danger')
                return render_template('register.html')

            # -------- VALIDATIONS -------- #
            if not validate_email(email):
                flash('Invalid email format', 'danger')
                return render_template('register.html')

            if not validate_phone(phone_number):
                flash('Invalid phone number (10 digits required)', 'danger')
                return render_template('register.html')

            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return render_template('register.html')

            valid, msg = validate_password(password)
            if not valid:
                flash(msg, 'danger')
                return render_template('register.html')

            # -------- CHECK EXISTING USER -------- #
            try:
                if users_collection.find_one({'email': email}):
                    flash('Email already registered', 'danger')
                    return render_template('register.html')
            except Exception as db_error:
                flash(f'Database error: {db_error}', 'danger')
                return render_template('register.html')

            # -------- OTP GENERATION (SAFE) -------- #
            try:
                otp_code = generate_otp(email, 'registration')
            except Exception as otp_error:
                print("OTP Error:", otp_error)
                otp_code = None

            if not otp_code:
                flash('Failed to generate OTP. Please try again', 'danger')
                return render_template('register.html')

            # -------- STORE IN SESSION -------- #
            try:
                session['temp_registration'] = {
                    'email': email,
                    'password_hash': generate_password_hash(password),
                    'full_name': full_name,
                    'phone_number': phone_number,
                    'date_of_birth': date_of_birth,
                    'address': address,
                    'occupation': occupation,
                    'annual_income': annual_income,
                    'otp_code': otp_code
                }
            except Exception as session_error:
                flash(f'Session error: {session_error}', 'danger')
                return render_template('register.html')

            flash(f'OTP sent to {email}. Please verify to complete registration', 'info')
            return redirect(url_for('verify_otp_page', purpose='registration'))

        except Exception as e:
            import traceback
            traceback.print_exc()  # 🔥 FULL DEBUG
            flash(f'Registration Error: {str(e)}', 'danger')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if is_account_locked(email):
            flash(f'Account locked. Try again after {Config.LOCKOUT_TIME_MINUTES} minutes', 'danger')
            return render_template('login.html')
        
        user = users_collection.find_one({'email': email})
        
        if user and check_password_hash(user['password_hash'], password):
            if not user.get('is_active', True):
                flash('Account is deactivated. Contact support', 'danger')
                return render_template('login.html')
            
            clear_failed_logins(email)
            
            if user.get('two_factor_enabled', True):
                otp_code = generate_otp(email, 'login')
                if otp_code:
                    session['login_email'] = email
                    flash('OTP sent to your email. Please verify to login', 'info')
                    return redirect(url_for('verify_otp_page', purpose='login'))
                else:
                    flash('Failed to send OTP. Please try again', 'danger')
                    return render_template('login.html')
            else:
                session['user_email'] = email
                session['two_factor_verified'] = True
                users_collection.update_one(
                    {'email': email},
                    {'$set': {'last_login': datetime.datetime.now()}}
                )
                add_notification(user['account_number'], "Welcome Back!", 
                               f"Welcome back {user['full_name']}! You have logged in successfully.", "success")
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
        else:
            record_failed_login(email)
            flash('Invalid email or password', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp_page():
    purpose = request.args.get('purpose') or request.form.get('purpose') or 'login'
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        
        if purpose == 'registration':
            temp_data = session.get('temp_registration')
            if not temp_data:
                flash('Registration session expired', 'danger')
                return redirect(url_for('register'))
            
            if verify_otp(temp_data['email'], otp_code, 'registration'):
                account_number = User.generate_account_number()
                user = User(
                    email=temp_data['email'],
                    password_hash=temp_data['password_hash'],
                    full_name=temp_data['full_name'],
                    account_number=account_number,
                    phone_number=temp_data['phone_number'],
                    address=temp_data.get('address'),
                    date_of_birth=temp_data.get('date_of_birth'),
                    occupation=temp_data.get('occupation'),
                    annual_income=temp_data.get('annual_income', 0),
                    is_verified=True
                )
                
                user.balance = 1000.0
                user.credit_score = calculate_credit_score(user.to_dict())
                
                users_collection.insert_one(user.to_dict())
                session.pop('temp_registration', None)
                
                welcome_transaction = Transaction(
                    transaction_id=str(uuid.uuid4()),
                    account_number=account_number,
                    transaction_type='credit',
                    amount=1000.0,
                    description='Welcome Bonus - Thank you for joining SecureBank!',
                    balance_after=1000.0
                )
                transactions_collection.insert_one(welcome_transaction.to_dict())
                
                reward_obj = Reward(account_number=account_number)
                rewards_collection.insert_one(reward_obj.to_dict())
                
                flash('Registration successful! Please login', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid or expired OTP', 'danger')
                return render_template('verify_otp.html', purpose=purpose, email=temp_data['email'])
        
        elif purpose == 'login':
            email = session.get('login_email')
            if not email:
                flash('Login session expired', 'danger')
                return redirect(url_for('login'))
            
            if verify_otp(email, otp_code, 'login'):
                session['user_email'] = email
                session['two_factor_verified'] = True
                session.pop('login_email', None)
                
                user = users_collection.find_one({'email': email})
                users_collection.update_one(
                    {'email': email},
                    {'$set': {'last_login': datetime.datetime.now()}}
                )
                
                add_notification(user['account_number'], "Login Alert", 
                               f"You have logged in from {request.remote_addr}", "info")
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid or expired OTP', 'danger')
                return render_template('verify_otp.html', purpose=purpose)
        
        elif purpose == 'transaction':
            email = session.get('user_email')
            if not email:
                flash('Session expired', 'danger')
                return redirect(url_for('login'))
            
            transaction_data = session.get('pending_transaction')
            if not transaction_data:
                flash('No pending transaction', 'danger')
                return redirect(url_for('transfer'))
            
            if verify_otp(email, otp_code, 'transaction'):
                result = process_transaction(transaction_data)
                session.pop('pending_transaction', None)
                
                if result:
                    flash('Transaction completed successfully!', 'success')
                    return redirect(url_for('transactions'))
                else:
                    flash('Transaction failed', 'danger')
                    return redirect(url_for('transfer'))
            else:
                flash('Invalid or expired OTP', 'danger')
                return render_template('verify_otp.html', purpose=purpose, email=email)
        
        elif purpose == 'biometric':
            email = session.get('user_email')
            if verify_otp(email, otp_code, 'biometric'):
                session['biometric_verified'] = True
                flash('Biometric verification successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid OTP', 'danger')
                return render_template('verify_otp.html', purpose=purpose)
    
    return render_template('verify_otp.html', purpose=purpose)


@app.route('/dashboard')
@login_required
@two_factor_required
def dashboard():
    user = users_collection.find_one({'email': session['user_email']})
    
    recent_transactions = list(transactions_collection.find(
        {'account_number': user['account_number']}
    ).sort('timestamp', -1).limit(10))
    
    reward = rewards_collection.find_one({'account_number': user['account_number']})
    benefits = get_tier_benefits(reward['tier'] if reward else 'bronze')
    
    active_loans = list(loans_collection.find(
        {'account_number': user['account_number'], 'status': 'active'}
    ))
    
    active_investments = list(investments_collection.find(
        {'account_number': user['account_number'], 'status': 'active'}
    ))
    
    pending_bills = list(bills_collection.find(
        {'account_number': user['account_number'], 'status': 'pending'}
    ))
    
    unread_notifications = list(notifications_collection.find(
        {'account_number': user['account_number'], 'is_read': False}
    ).sort('timestamp', -1).limit(5))
    
    spending_data = list(transactions_collection.find(
        {'account_number': user['account_number'], 'transaction_type': {'$in': ['debit', 'transfer']}}
    ).sort('timestamp', -1).limit(50))
    
    categories = defaultdict(float)
    for tx in spending_data:
        category = tx.get('category', 'other')
        categories[category] += tx['amount']
    
    category_names = list(categories.keys())
    category_values = list(categories.values())
    
    qr_code = generate_qr(f"pay:{user['account_number']}")
    insights = get_financial_insights(user['account_number'])
    
    return render_template('dashboard.html', 
                         user=user, 
                         transactions=recent_transactions, 
                         format_currency=format_currency,
                         reward=reward,
                         benefits=benefits,
                         active_loans=active_loans,
                         active_investments=active_investments,
                         pending_bills=pending_bills,
                         unread_notifications=unread_notifications,
                         category_names=category_names,
                         category_values=category_values,
                         qr_code=qr_code,
                         insights=insights)

@app.route('/apply-loan', methods=['GET', 'POST'])
@login_required
@two_factor_required
def apply_loan():
    user = users_collection.find_one({'email': session['user_email']})

    if request.method == 'POST':
        loan_type = request.form.get('loan_type')
        amount = float(request.form.get('amount', 0))
        tenure = int(request.form.get('tenure', 12))

        # Eligibility check
        if amount > user['annual_income'] * 0.5:
            flash('Loan amount exceeds eligibility limit (50% of annual income)', 'danger')
            return render_template('apply_loan.html', user=user)

        if user['credit_score'] < 650:
            flash('Credit score too low for loan approval', 'danger')
            return render_template('apply_loan.html', user=user)

        # Interest rates
        interest_rates = {
            'personal': Config.PERSONAL_LOAN_RATE,
            'home': Config.HOME_LOAN_RATE,
            'car': Config.CAR_LOAN_RATE,
            'education': Config.EDUCATION_LOAN_RATE
        }

        rate = interest_rates.get(loan_type, Config.PERSONAL_LOAN_RATE)

        # ✅ EMI Calculation (IMPORTANT FIX)
        monthly_rate = rate / 12 / 100

        emi = (amount * monthly_rate * (1 + monthly_rate) ** tenure) / \
              ((1 + monthly_rate) ** tenure - 1)

        total_payable = emi * tenure
        total_interest = total_payable - amount

        # ✅ FIXED Loan Object
        loan = Loan(
            account_number=user['account_number'],
            loan_id=str(uuid.uuid4()),
            loan_type=loan_type,
            principal_amount=amount,     # ✅ FIXED
            tenure_months=tenure,        # ✅ FIXED
            interest_rate=rate,
            monthly_emi=emi,
            total_interest=total_interest,
            total_payable=total_payable
        )

        loans_collection.insert_one(loan.__dict__)

        add_notification(
            user['account_number'],
            "Loan Application Submitted",
            f"Your {loan_type} loan application for ${amount:,.2f} has been submitted",
            "info"
        )

        flash('Loan application submitted successfully!', 'success')
        return redirect(url_for('loans'))

    return render_template('apply_loan.html', user=user)
@app.route('/loans')
@login_required
@two_factor_required
def loans():
    user = users_collection.find_one({'email': session['user_email']})
    loans_list = list(loans_collection.find({'account_number': user['account_number']}).sort('start_date', -1))
    return render_template('loans.html', user=user, loans=loans_list, format_currency=format_currency)

@app.route('/invest', methods=['GET', 'POST'])
@login_required
@two_factor_required
def invest():
    user = users_collection.find_one({'email': session['user_email']})

    if request.method == 'POST':
        investment_type = request.form.get('investment_type')
        amount = float(request.form.get('amount', 0))

        # ✅ FIX: use tenure (NOT duration or plan)
        tenure = int(request.form.get('tenure', 12))

        # interest logic
        fd_rates = {
            6: 5.5,
            12: 6.0,
            24: 6.5,
            60: 7.0
        }

        if investment_type == "fixed_deposit":
            rate = fd_rates.get(tenure, 6.0)
        else:
            rate = 10  # default for MF/stocks

        # maturity calculation
        maturity_amount = amount * (1 + (rate / 100) * (tenure / 12))

        start_date = datetime.datetime.now()
        maturity_date = start_date + timedelta(days=30 * tenure)

        # ✅ FIX: include ALL required fields
        investment = Investment(
            investment_id=str(uuid.uuid4()),
            account_number=user['account_number'],
            investment_type=investment_type,
            amount=amount,
            tenure_months=tenure,   # ✅ CORRECT
            interest_rate=rate,
            maturity_amount=maturity_amount,
            start_date=start_date,
            maturity_date=maturity_date
        )

        investments_collection.insert_one(investment.to_dict())

        flash('Investment successful!', 'success')
        return redirect(url_for('investments'))

    return render_template('invest.html', user=user, format_currency=format_currency)

@app.context_processor
def inject_functions():
    return dict(
        format_currency=format_currency,
        now=datetime.datetime.now()   # ✅ ADD THIS
    )

@app.route('/investments')
@login_required
@two_factor_required
def investments():
    user = users_collection.find_one({'email': session['user_email']})
    investments_list = list(investments_collection.find({'account_number': user['account_number']}).sort('start_date', -1))
    return render_template('investments.html', user=user, investments=investments_list, format_currency=format_currency)

@app.route('/pay-bills', methods=['GET', 'POST'])
@login_required
@two_factor_required
def pay_bills():
    user = users_collection.find_one({'email': session['user_email']})
    
    if request.method == 'POST':
        bill_type = request.form.get('bill_type')
        biller_name = request.form.get('biller_name')
        biller_account = request.form.get('biller_account')
        amount = float(request.form.get('amount', 0))
        due_date_str = request.form.get('due_date')
        
        due_date = datetime.datetime.strptime(due_date_str, '%Y-%m-%d') if due_date_str else datetime.datetime.now() + datetime.timedelta(days=15)
        
        bill = Bill(
            account_number=user['account_number'],
            bill_type=bill_type,
            biller_name=biller_name,
            biller_account=biller_account,
            amount=amount,
            due_date=due_date
        )
        
        bills_collection.insert_one(bill.to_dict())
        
        flash('Bill added successfully!', 'success')
        return redirect(url_for('bills'))
    
    return render_template('pay_bills.html', user=user, bill_categories=Config.BILL_CATEGORIES, format_currency=format_currency)

@app.route('/bills')
@login_required
@two_factor_required
def bills():
    user = users_collection.find_one({'email': session['user_email']})
    bills_list = list(bills_collection.find({'account_number': user['account_number']}).sort('due_date', 1))
    return render_template('bills.html', user=user, bills=bills_list, format_currency=format_currency)

@app.route('/pay-bill/<bill_id>', methods=['POST'])
@login_required
@two_factor_required
def pay_bill(bill_id):
    user = users_collection.find_one({'email': session['user_email']})
    bill = bills_collection.find_one({'bill_id': bill_id, 'account_number': user['account_number']})
    
    if not bill:
        flash('Bill not found', 'danger')
        return redirect(url_for('bills'))
    
    total_amount = bill['amount'] + bill.get('late_fee', 0)
    
    if user['balance'] < total_amount:
        flash('Insufficient balance', 'danger')
        return redirect(url_for('bills'))
    
    new_balance = user['balance'] - total_amount
    users_collection.update_one(
        {'email': session['user_email']},
        {'$set': {'balance': new_balance}}
    )
    
    bills_collection.update_one(
        {'bill_id': bill_id},
        {'$set': {'status': 'paid', 'paid_date': datetime.datetime.now()}}
    )
    
    transaction = Transaction(
        account_number=user['account_number'],
        transaction_type='debit',
        amount=total_amount,
        description=f"Bill Payment - {bill['bill_type']} - {bill['biller_name']}",
        balance_after=new_balance,
        category='bills'
    )
    transactions_collection.insert_one(transaction.to_dict())
    
    calculate_rewards(user['account_number'], total_amount)
    
    add_notification(user['account_number'], "Bill Paid", 
                    f"Successfully paid {bill['bill_type']} bill of ${total_amount:,.2f}", "success")
    
    flash('Bill paid successfully!', 'success')
    return redirect(url_for('bills'))

@app.route('/rewards')
@login_required
@two_factor_required
def rewards_page():
    user = users_collection.find_one({'email': session['user_email']})
    reward = rewards_collection.find_one({'account_number': user['account_number']})
    
    if not reward:
        reward = Reward(account_number=user['account_number'])
    
    benefits = get_tier_benefits(reward['tier'])
    
    next_tier_points = 0
    if reward['tier'] == 'bronze':
        next_tier_points = 10000 - reward['points']
    elif reward['tier'] == 'silver':
        next_tier_points = 25000 - reward['points']
    elif reward['tier'] == 'gold':
        next_tier_points = 50000 - reward['points']
    
    return render_template('rewards.html', user=user, reward=reward, benefits=benefits, 
                          next_tier_points=next_tier_points, format_currency=format_currency)

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
@two_factor_required
def transfer():
    user = users_collection.find_one({'email': session['user_email']})
    
    if request.method == 'POST':
        recipient_account = request.form.get('recipient_account', '').strip()
        amount = float(request.form.get('amount', 0))
        description = request.form.get('description', '')
        
        if not recipient_account or amount <= 0:
            flash('Invalid input', 'danger')
            return render_template('transfer.html', user=user)
        
        if amount > Config.MAX_TRANSACTION_AMOUNT:
            flash(f'Amount exceeds maximum limit of {format_currency(Config.MAX_TRANSACTION_AMOUNT)}', 'danger')
            return render_template('transfer.html', user=user)
        
        if amount > user['balance']:
            flash('Insufficient balance', 'danger')
            return render_template('transfer.html', user=user)
        
        recipient = users_collection.find_one({'account_number': recipient_account})
        if not recipient:
            flash('Recipient account not found', 'danger')
            return render_template('transfer.html', user=user)
        
        if recipient_account == user['account_number']:
            flash('Cannot transfer to your own account', 'danger')
            return render_template('transfer.html', user=user)
        
        otp_code = generate_otp(session['user_email'], 'transaction')
        if not otp_code:
            flash('Failed to generate OTP. Please try again', 'danger')
            return render_template('transfer.html', user=user)
        
        session['pending_transaction'] = {
            'sender_email': session['user_email'],
            'recipient_account': recipient_account,
            'amount': amount,
            'description': description
        }
        
        flash('OTP sent to your email. Please verify to complete transaction', 'info')
        return redirect(url_for('verify_otp_page', purpose='transaction'))
    
    return render_template('transfer.html', user=user, format_currency=format_currency)

@app.route('/transactions')
@login_required
@two_factor_required
def transactions():
    user = users_collection.find_one({'email': session['user_email']})
    all_transactions = list(transactions_collection.find(
        {'account_number': user['account_number']}
    ).sort('timestamp', -1))
    return render_template('transactions.html', user=user, transactions=all_transactions, format_currency=format_currency)

@app.route('/analytics')
@login_required
@two_factor_required
def analytics():
    user = users_collection.find_one({'email': session['user_email']})
    
    current_year = datetime.datetime.now().year
    start_date = datetime.datetime(current_year, 1, 1)
    
    yearly_transactions = list(transactions_collection.find({
        'account_number': user['account_number'],
        'timestamp': {'$gte': start_date}
    }))
    
    monthly_data = defaultdict(float)
    category_data = defaultdict(float)
    
    for tx in yearly_transactions:
        if tx['transaction_type'] in ['debit', 'transfer']:
            month = tx['timestamp'].strftime('%B')
            monthly_data[month] += tx['amount']
            category = tx.get('category', 'other')
            category_data[category] += tx['amount']
    
    months = list(calendar.month_name)[1:]
    spending_by_month = [monthly_data.get(month, 0) for month in months]
    
    categories = list(category_data.keys())
    category_amounts = list(category_data.values())
    
    insights = get_financial_insights(user['account_number'])
    
    total_income = sum(tx['amount'] for tx in yearly_transactions if tx['transaction_type'] == 'credit')
    total_expenses = sum(tx['amount'] for tx in yearly_transactions if tx['transaction_type'] in ['debit', 'transfer'])
    savings_rate = ((total_income - total_expenses) / total_income * 100) if total_income > 0 else 0
    
    return render_template('analytics.html', user=user, months=months, spending_by_month=spending_by_month,
                          categories=categories, category_amounts=category_amounts,
                          insights=insights, savings_rate=savings_rate, format_currency=format_currency)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
@two_factor_required
def profile():
    user = users_collection.find_one({'email': session['user_email']})
    
    if request.method == 'POST':
        updates = {}
        
        if request.form.get('full_name'):
            updates['full_name'] = request.form['full_name']
        if request.form.get('phone_number'):
            if validate_phone(request.form['phone_number']):
                updates['phone_number'] = request.form['phone_number']
            else:
                flash('Invalid phone number', 'danger')
                return render_template('profile.html', user=user)
        if request.form.get('address'):
            updates['address'] = request.form['address']
        if request.form.get('occupation'):
            updates['occupation'] = request.form['occupation']
        if request.form.get('annual_income'):
            updates['annual_income'] = float(request.form['annual_income'])
        
        two_factor_enabled = request.form.get('two_factor_enabled') == 'on'
        updates['two_factor_enabled'] = two_factor_enabled
        
        if updates:
            users_collection.update_one(
                {'email': session['user_email']},
                {'$set': updates}
            )
            
            updated_user = users_collection.find_one({'email': session['user_email']})
            new_score = calculate_credit_score(updated_user)
            users_collection.update_one(
                {'email': session['user_email']},
                {'$set': {'credit_score': new_score}}
            )
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

@app.route('/biometric-setup', methods=['GET', 'POST'])
@login_required
@two_factor_required
def biometric_setup():
    user = users_collection.find_one({'email': session['user_email']})
    
    if request.method == 'POST':
        biometric_enabled = request.form.get('biometric_enabled') == 'on'
        
        users_collection.update_one(
            {'email': session['user_email']},
            {'$set': {'biometric_enabled': biometric_enabled}}
        )
        
        if biometric_enabled:
            biometric_collection.update_one(
                {'email': session['user_email']},
                {'$set': {'enabled': True, 'setup_date': datetime.datetime.now()}},
                upsert=True
            )
            flash('Biometric authentication enabled successfully!', 'success')
        else:
            flash('Biometric authentication disabled', 'info')
        
        return redirect(url_for('profile'))
    
    return render_template('biometric_setup.html', user=user)

@app.route('/biometric-verify', methods=['GET', 'POST'])
@login_required
def biometric_verify():
    if request.method == 'POST':
        otp_code = generate_otp(session['user_email'], 'biometric')
        if otp_code:
            flash('OTP sent to your email for verification', 'info')
            return redirect(url_for('verify_otp_page', purpose='biometric'))
        else:
            flash('Failed to send OTP', 'danger')
            return render_template('biometric_verify.html')
    
    return render_template('biometric_verify.html')

@app.route('/notifications')
@login_required
@two_factor_required
def notifications():
    user = users_collection.find_one({'email': session['user_email']})
    notifications_list = list(notifications_collection.find(
        {'account_number': user['account_number']}
    ).sort('timestamp', -1))
    
    notifications_collection.update_many(
        {'account_number': user['account_number'], 'is_read': False},
        {'$set': {'is_read': True}}
    )
    
    return render_template('notifications.html', user=user, notifications=notifications_list)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
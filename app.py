# app.py
import os
import re
import hashlib
import secrets
import datetime
from functools import wraps
from typing import Optional

from flask import Flask, jsonify, request, render_template, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from cryptography.fernet import Fernet, InvalidToken
import jwt
import logging

# pysui imports (latest pysui)
from pysui import SuiConfig, SyncClient
from pysui.sui.sui_types.address import SuiAddress
from pysui.sui.sui_txn import SyncTransaction
from pysui.sui.sui_crypto import KeyPair, SignatureScheme, keypair_from_mnemonic, generate_mnemonic

app = Flask(__name__, template_folder='templates')
app.logger.setLevel(logging.INFO)

# ---------- Config ----------
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET'] = os.getenv('JWT_SECRET', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///wallet.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app, supports_credentials=True)

# Fernet key (must be provided in production as base64 urlsafe)
FERNET_KEY_ENV = os.getenv('FERNET_KEY')
if FERNET_KEY_ENV:
    FERNET_KEY = FERNET_KEY_ENV.encode()
else:
    FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

# Multi-network RPC map (override via env)
RPC_MAP = {
    'mainnet': os.getenv('SUI_RPC_MAINNET', 'https://fullnode.mainnet.sui.io:443'),
    'testnet': os.getenv('SUI_RPC_TESTNET', 'https://fullnode.testnet.sui.io:443'),
    'devnet' : os.getenv('SUI_RPC_DEVNET', 'https://fullnode.devnet.sui.io:443'),
}
DEFAULT_NETWORK = os.getenv('SUI_DEFAULT_NETWORK', 'testnet')

# ---------- DB models ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_hash = db.Column(db.String(256), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    accounts = db.relationship('Account', backref='user', lazy=True, cascade='all, delete-orphan')

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    address = db.Column(db.String(128), unique=True, nullable=False)
    nickname = db.Column(db.String(64))
    private_key_enc = db.Column(db.Text, nullable=False)
    mnemonic_enc = db.Column(db.Text)  # encrypted mnemonic (if created server-side)
    public_key = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=False)
    network = db.Column(db.String(16), default=DEFAULT_NETWORK)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class TransactionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    digest = db.Column(db.String(128))
    status = db.Column(db.String(32))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    kind = db.Column(db.String(32))
    amount = db.Column(db.Float)
    to_address = db.Column(db.String(128))

# ---------- helpers ----------
def encrypt_data(plain: str) -> str:
    return fernet.encrypt(plain.encode()).decode()

def decrypt_data(enc: str) -> str:
    try:
        return fernet.decrypt(enc.encode()).decode()
    except InvalidToken:
        raise ValueError("Failed to decrypt")

def validate_address(a: str) -> bool:
    return bool(re.match(r'^0x[a-fA-F0-9]{64}$', str(a)))

def validate_amount(amount) -> bool:
    try:
        a = float(amount)
        return a > 0 and a < 10_000_000
    except Exception:
        return False

def get_sui_client(network: str):
    rpc = RPC_MAP.get(network, RPC_MAP[DEFAULT_NETWORK])
    cfg = SuiConfig(rpc_url=rpc)
    return SyncClient(cfg)

# ---------- JWT ----------
def create_jwt(user_id: int) -> str:
    payload = {'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=12)}
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')

def decode_jwt(token: str) -> Optional[int]:
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        return payload.get('user_id')
    except Exception:
        return None

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        auth = request.headers.get('Authorization')
        if auth and auth.startswith('Bearer '):
            token = auth.split(' ',1)[1]
        else:
            token = request.cookies.get('access_token')
        if not token:
            return jsonify({'error':'Authentication required'}), 401
        user_id = decode_jwt(token)
        if not user_id:
            return jsonify({'error':'Invalid or expired token'}), 401
        return f(user_id, *args, **kwargs)
    return wrapper

# ---------- routes ----------
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    password = data.get('password','')
    if not isinstance(password, str) or len(password) < 8:
        return jsonify({'error':'Password must be at least 8 characters'}), 400
    user_hash = hashlib.sha256(password.encode()).hexdigest()
    user = User.query.filter_by(user_hash=user_hash).first()
    if not user:
        user = User(user_hash=user_hash)
        db.session.add(user); db.session.commit()
    token = create_jwt(user.id)
    resp = make_response(jsonify({'success': True, 'token': token}))
    # also set cookie for browser credentialed requests
    resp.set_cookie('access_token', token, httponly=True, secure=(os.getenv('DISABLE_SECURE_COOKIE','0')!='1'), samesite='Lax', max_age=12*3600)
    return resp

@app.route('/api/account/generate', methods=['POST'])
@require_auth
def generate_account(user_id):
    data = request.get_json() or {}
    network = data.get('network') or DEFAULT_NETWORK
    # generate mnemonic and keypair using pysui helper
    mnemonic = generate_mnemonic(12)  # returns list or string depending on pysui; handle both
    if isinstance(mnemonic, list):
        mnemonic_phrase = " ".join(mnemonic)
    else:
        mnemonic_phrase = mnemonic
    keypair = keypair_from_mnemonic(mnemonic_phrase, SignatureScheme.ED25519)
    priv_hex = keypair.to_bytes().hex()
    pub_hex = keypair.public_key.to_bytes().hex()
    address = str(keypair.to_address())
    enc_priv = encrypt_data(priv_hex)
    enc_mnemonic = encrypt_data(mnemonic_phrase)
    is_first = Account.query.filter_by(user_id=user_id, network=network).count() == 0
    acc = Account(user_id=user_id, address=address, nickname=f'Account-{network}', private_key_enc=enc_priv, mnemonic_enc=enc_mnemonic, public_key=pub_hex, is_active=is_first, network=network)
    db.session.add(acc); db.session.commit()
    # return wallet and mnemonic (frontend shows guarded modal)
    accounts_q = Account.query.filter_by(user_id=user_id, network=network).all()
    safe_accounts = [{'id':a.id,'address':a.address,'nickname':a.nickname,'is_active':a.is_active} for a in accounts_q]
    active_acc_id = next((a.id for a in accounts_q if a.is_active), None)
    return jsonify({'success': True, 'account': {'id': acc.id, 'address': acc.address, 'nickname': acc.nickname, 'is_active': acc.is_active}, 'mnemonic': mnemonic_phrase, 'accounts': safe_accounts, 'active_account': active_acc_id})

@app.route('/api/account/recover', methods=['POST'])
@require_auth
def recover_account(user_id):
    data = request.get_json() or {}
    mnemonic = data.get('mnemonic','').strip()
    network = data.get('network') or DEFAULT_NETWORK
    if not mnemonic or len(mnemonic.split()) != 12:
        return jsonify({'error':'Invalid 12-word seed phrase'}), 400
    try:
        keypair = keypair_from_mnemonic(mnemonic, SignatureScheme.ED25519)
        priv_hex = keypair.to_bytes().hex()
        pub_hex = keypair.public_key.to_bytes().hex()
        address = str(keypair.to_address())
        enc_priv = encrypt_data(priv_hex)
        enc_mnemonic = encrypt_data(mnemonic)
        is_first = Account.query.filter_by(user_id=user_id, network=network).count() == 0
        acc = Account(user_id=user_id, address=address, nickname=f'Recovered-{network}', private_key_enc=enc_priv, mnemonic_enc=enc_mnemonic, public_key=pub_hex, is_active=is_first, network=network)
        db.session.add(acc); db.session.commit()
        accounts_q = Account.query.filter_by(user_id=user_id,network=network).all()
        safe_accounts = [{'id':a.id,'address':a.address,'nickname':a.nickname,'is_active':a.is_active} for a in accounts_q]
        active_acc_id = next((a.id for a in accounts_q if a.is_active), None)
        return jsonify({'success': True, 'account': {'id': acc.id, 'address': acc.address}, 'accounts': safe_accounts, 'active_account': active_acc_id})
    except Exception as e:
        app.logger.exception('recover error')
        return jsonify({'error':str(e)}), 500

@app.route('/api/account/list', methods=['GET'])
@require_auth
def list_accounts(user_id):
    network = request.args.get('network') or request.headers.get('X-SUI-NETWORK') or DEFAULT_NETWORK
    accounts_q = Account.query.filter_by(user_id=user_id, network=network).all()
    safe_accounts = [{'id':a.id,'address':a.address,'nickname':a.nickname,'is_active':a.is_active} for a in accounts_q]
    active_acc_id = next((a.id for a in accounts_q if a.is_active), None)
    return jsonify({'accounts': safe_accounts, 'active_account': active_acc_id})

@app.route('/api/account/switch', methods=['POST'])
@require_auth
def switch_account(user_id):
    data = request.get_json() or {}
    acc_id = data.get('account_id')
    network = data.get('network') or request.headers.get('X-SUI-NETWORK') or DEFAULT_NETWORK
    if not acc_id:
        return jsonify({'error':'account_id required'}), 400
    acc = Account.query.filter_by(id=acc_id, user_id=user_id, network=network).first()
    if not acc: return jsonify({'error':'Account not found'}), 404
    Account.query.filter_by(user_id=user_id, network=network).update({'is_active': False})
    acc.is_active = True
    db.session.commit()
    return jsonify({'success': True, 'active_account': acc.id})

@app.route('/api/account/balance/<network>', methods=['GET'])
@require_auth
def get_balance(user_id, network):
    acc = Account.query.filter_by(user_id=user_id, is_active=True, network=network).first()
    if not acc: return jsonify({'error':'No active account'}), 400
    client = get_sui_client(network)
    try:
        address_obj = SuiAddress(acc.address)
        res = client.get_gas(address_obj)
        total = 0
        if res.is_ok():
            coins = res.result_data.data
            total = sum(int(c.balance) for c in coins)
        return jsonify({'balance': total / 1_000_000_000, 'address': acc.address})
    except Exception as e:
        app.logger.exception('balance error')
        return jsonify({'error':'Failed to fetch balance', 'detail':str(e)}), 500

@app.route('/api/transaction/send/<network>', methods=['POST'])
@require_auth
def send_transaction(user_id, network):
    data = request.get_json() or {}
    recipient = data.get('recipient')
    amount = data.get('amount')
    if not recipient or not validate_address(recipient):
        return jsonify({'error':'Invalid recipient address'}), 400
    if not validate_amount(amount):
        return jsonify({'error':'Invalid amount'}), 400
    acc = Account.query.filter_by(user_id=user_id, is_active=True, network=network).first()
    if not acc: return jsonify({'error':'No active account'}), 400
    client = get_sui_client(network)
    try:
        priv_hex = decrypt_data(acc.private_key_enc)
        keypair = KeyPair.from_bytes(bytes.fromhex(priv_hex))
        amount_mist = int(float(amount) * 1_000_000_000)
        txn = SyncTransaction(client=client, initial_sender=SuiAddress(acc.address))
        scres = txn.split_coin(coin=txn.gas, amounts=[amount_mist])
        txn.transfer_objects(transfers=[scres], recipient=SuiAddress(recipient))
        tx_result = txn.execute(use_gas_object=txn.gas, signer=keypair)
        if tx_result.is_ok():
            digest = tx_result.result_data.digest
            db.session.add(TransactionLog(account_id=acc.id, digest=digest, status='success', kind='transfer', amount=float(amount), to_address=recipient))
            db.session.commit()
            return jsonify({'success': True, 'digest': digest})
        else:
            return jsonify({'error': str(tx_result.result_string)}), 500
    except Exception as e:
        app.logger.exception('send tx error')
        return jsonify({'error':'Transaction failed', 'detail':str(e)}), 500

@app.route('/api/account/history/<network>', methods=['GET'])
@require_auth
def tx_history(user_id, network):
    acc = Account.query.filter_by(user_id=user_id, is_active=True, network=network).first()
    if not acc: return jsonify({'error':'No active account'}), 400
    txs = TransactionLog.query.filter_by(account_id=acc.id).order_by(TransactionLog.timestamp.desc()).limit(50).all()
    result = [{'digest':t.digest,'status':t.status,'timestamp':t.timestamp.isoformat(),'type':t.kind or 'transfer','amount':t.amount or 0,'to': t.to_address or ''} for t in txs]
    return jsonify({'transactions': result})

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))

pip install google-auth requests flask pyotp


from flask import Flask, redirect, url_for, session, request, jsonify
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import pyotp

app = Flask(__name__)
app.secret_key = 'YOUR_SECRET_KEY'

GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID'
GOOGLE_CLIENT_SECRET = 'YOUR_GOOGLE_CLIENT_SECRET'

users = {}  # In-memory store for user data. Use a database in production.

@app.route('/')
def index():
    if 'google_id' in session:
        return 'Logged in as: ' + session['google_id']
    return 'You are not logged in'

@app.route('/login')
def login():
    google_login_url = (
        'https://accounts.google.com/o/oauth2/auth?'
        'response_type=code&'
        'client_id={}&'
        'redirect_uri={}&'
        'scope=openid%20email%20profile'.format(
            GOOGLE_CLIENT_ID,
            url_for('oauth2callback', _external=True)
        )
    )
    return redirect(google_login_url)

@app.route('/oauth2callback')
def oauth2callback():
    code = request.args.get('code')
    token_url = 'https://oauth2.googleapis.com/token'
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': url_for('oauth2callback', _external=True),
        'grant_type': 'authorization_code'
    }
    token_response = requests.post(token_url, data=token_data)
    token_response_data = token_response.json()
    id_info = id_token.verify_oauth2_token(
        token_response_data['id_token'],
        google_requests.Request(),
        GOOGLE_CLIENT_ID
    )
    google_id = id_info['sub']
    session['google_id'] = google_id
    if google_id not in users:
        users[google_id] = {
            'email': id_info['email'],
            'otp_secret': pyotp.random_base32()
        }
    return redirect(url_for('verify_2fa'))

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if request.method == 'POST':
        otp = request.form['otp']
        user = users[session['google_id']]
        totp = pyotp.TOTP(user['otp_secret'])
        if totp.verify(otp):
            session['authenticated'] = True
            return redirect(url_for('index'))
        return 'Invalid OTP'
    return '''
        <form method="post">
            <label for="otp">Enter OTP:</label>
            <input type="text" id="otp" name="otp">
            <input type="submit" value="Verify">
        </form>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, jsonify, request
from datetime import datetime, timedelta
import re
import bcrypt


app = Flask(__name__)
# Dictionary to store the number of failed attempts for each username
failed_attempts = {}
# Dictionary to store the last failed attempt time for each username
last_attempt_time = {}


@app.route('/create_account', methods=['POST'])
def create_account():
    # Parse the JSON payload
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # check if user already exist
    if is_username_exist(username):
        return jsonify(success=False, reason='username already exist'), 400
    # Validate the input fields
    if not username:
        return jsonify(success=False, reason='username field is required'), 400
    if not isinstance(username, str):
        return jsonify(success=False, reason='username field must be a string'), 400
    if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
        return jsonify(success=False, reason='username field must be between 3 and 32 characters and can only contain letters, numbers, and underscores'), 400

    if not password:
        return jsonify(success=False, reason='password field is required'), 400
    if not isinstance(password, str):
        return jsonify(success=False, reason='password field must be a string'), 400
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,32}$', password):
        return jsonify(success=False, reason='password field must be between 8 and 32 characters and contain at least one uppercase letter, one lowercase letter, and one number'), 400

    # Hash the password before storing it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with open('accounts.txt', 'a') as f:
        f.write(f'{username},{hashed_password.decode()}\n')

    return jsonify(success=True, reason='Account created successfully'), 201


@app.route('/verify_account', methods=['POST'])
def verify_account():
    # Parse the JSON payload
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the user has exceeded the maximum number of failed attempts
    if username in failed_attempts and failed_attempts[username] >= 5:
        last_failed_time = last_attempt_time[username]
        elapsed_time = datetime.now() - last_failed_time
        if elapsed_time < timedelta(minutes=1):
            wait_time = 60 - elapsed_time.seconds
            return jsonify(success=False, reason=f'Too many failed attempts. Please wait {wait_time} seconds before trying again.'), 429

    if not verify_user_account(username, password):
        if username in failed_attempts:
            failed_attempts[username] += 1
        else:
            failed_attempts[username] = 1
        last_attempt_time[username] = datetime.now()
        return jsonify(success=False, reason='Invalid username or password'), 401

    if username in failed_attempts:
        del failed_attempts[username]
    if username in last_attempt_time:
        del last_attempt_time[username]
    return jsonify(success=True), 200


def verify_user_account(username, password):
    with open('accounts.txt', 'r') as f:
        for line in f:
            # Strip the newline character and split the line into username and password
            user, pwd = line.strip().split(',')
            if user == username and bcrypt.checkpw(password.encode('utf-8'), pwd.encode('utf-8')):
                return True
    return False


def is_username_exist(username):
    with open('accounts.txt', 'r') as f:
        for line in f:
            # Strip the newline character and split the line into username and password
            user, _ = line.strip().split(',')
            if user == username:
                return True
    return False


if __name__ == '__main__':
    app.run(debug=True)
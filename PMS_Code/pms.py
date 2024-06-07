'''
-> Microsoft Policy for Creating strong passwords

Password security starts with creating a strong password. A strong password is:

- At least 12 characters long but 14 or more is better. - Done

- A combination of uppercase letters, lowercase letters, numbers, and symbols. - Done

- Not a word that can be found in a dictionary or the name of a person, character, product, or organization.

- Significantly different from your previous passwords.

- Easy for you to remember but difficult for others to guess. Consider using a memorable phrase like "6MonkeysRLooking^".
'''

# Libraries
from flask import Flask, request, jsonify
import hashlib
import requests
import pymongo
import json
import threading
import jwt
import secrets
import re
import string

app = Flask(__name__)

# Define locks
file_lock = threading.Lock()
db_lock = threading.Lock()

# Secret key for JWT token encoding/decoding
SECRET_KEY = secrets.token_urlsafe(64)

def haveibeenpwnd_checking(password):
    sha1 = hashlib.sha1()
    sha1.update(password.encode('utf-8'))
    hashed_password = sha1.hexdigest()

    url = "https://api.pwnedpasswords.com/range/" + hashed_password[:5]
    s = requests.session()
    pwnd = s.get(url, verify=False)
    if hashed_password[5:].upper() in pwnd.text:
        return True
    else:
        return False

def sha256_hashing(password):
    # Password Hashing
    encoded_pass = password.encode('utf-8')
    sha256_hasher = hashlib.sha256()
    sha256_hasher.update(encoded_pass)
    return sha256_hasher.hexdigest()

def generate_jwt_token(username):
    payload = {"username": username}
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def decode_jwt_token(token):
    try:
        decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return decoded_payload
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired."}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token."}

def database_insertition(username, password):
    mongo_uri = "mongodb://localhost:27017"# "mongodb+srv://dharmikpatel08:RoeDKw9EC5T4p4dQ@pms.kzqukrf.mongodb.net/?retryWrites=true&w=majority"
    client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)

    # Access a specific database
    db = client["pms"]

    # Define a sample document
    content = {
        "username": username,
        "password": sha256_hashing(password)
    }

    # Insert the document into a collection
    collection = db["pms"]
    result = collection.insert_one(content)

    # Print the inserted document's ID
    # print(f"Inserted document ID: {result.inserted_id}")

def database_reading(username, password):
    # Replace the connection string with your MongoDB connection string
    # You can get this from your MongoDB Atlas dashboard or set up your local connection
    mongo_uri = "mongodb://localhost:27017"# "mongodb+srv://dharmikpatel08:RoeDKw9EC5T4p4dQ@pms.kzqukrf.mongodb.net/?retryWrites=true&w=majority"
    
    # Add tlsAllowInvalidCertificates option to ignore SSL certificate validation
    client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)

    # Access a specific database
    db = client["pms"]

    # Access the collection
    collection = db["pms"]

    data = {"username": username, "password": sha256_hashing(password)}
    # Query all documents in the collection
    cursor = collection.find(data)
    print(cursor)

    # Iterate through the documents and print them
    for document in cursor:
        if document['username']:
            return True
        else:
            return False

def checking_password_security(password):
    haslowercase_letter = True
    hasuppercase_letter = True
    hasnumber = True

    # Upper and Lower case Logic
    for letter in password:
        if letter.isupper():
            hasuppercase_letter = False
        if letter.islower():
            haslowercase_letter = False

    # Numbers and Special Chars Logic
    expression = "\d"
    hasnumber = bool(re.search(expression, password))
    expression_for_specialchars = '[^A-Za-z0-9\s]'
    hasspecial_chars = bool(re.search(expression_for_specialchars, password))

    # Main Program Conditions
    if len(password) <= 12:
        return "Your password do not have a length of 12. Please make sure to atleast use 12 characters long password."
    elif hasuppercase_letter:
        return "Your password do not have upper case letter."
    elif haslowercase_letter:
        return "Your password do not have lower case."
    elif hasnumber==False:
        return "Your password do not have a number."
    elif hasspecial_chars==False:
        return "Your password do not have special characters."
    else:
        return "Password is Valid"


# Generating secure password using Secrets
def random_password_generator(length):
    policy = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation

    password1 = ''
    password2 = ''
    password3 = ''
    for i in range(16):
        password1 += secrets.choice(policy)
        password2 += secrets.choice(policy)
        password3 += secrets.choice(policy)
        
    final_password = ''
    for i in range(14):
        final_password += secrets.choice(password1 + password2 + password3)
    
    return final_password


@app.route('/api/policy_update', methods=['POST'])
def policy_update():
    # Authentication with JWT token required
    token = request.headers.get("Authorization")
    if not token:
        return {"error": "Authorization token required."}, 401

    decoded_payload = decode_jwt_token(token)
    if "error" in decoded_payload:
        return decoded_payload, 401
    
    data = request.get_json()
    policy = data.get("policy")

    with file_lock:
        file = open("policy.json", "w")
        json_data = json.dumps({"policy": policy})
        file.write(json_data)
        file.close()

    return {'message': "Policy has been updated"}

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Ensure atomicity in database read operation
    with db_lock:
        checking_login = database_reading(username, password)

    if checking_login:
        token = generate_jwt_token(username)
        return {"message": "Login Successful", "token": token}
    else:
        return {"message": "Login Failed"}


@app.route('/api/user_creation', methods=['POST'])
def user_creation():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    token = generate_jwt_token(username)
    password_validation = secure_password_checker(password, token)

    # Ensure atomicity in database operations
    with db_lock:
        if "Password is Valid" == password_validation['message']:
            if database_reading(username, password):
                return {"message": "User already exists."}
            else:
                database_insertition(username, password)
                return {"message": "User has been created.", "token": token}
        else:
            return password_validation

@app.route('/api/batch_password_generation', methods=['POST'])
def batch_password_generation():
    # Authentication with JWT token required
    token = request.headers.get("Authorization")
    if not token:
        return {"error": "Authorization token required."}, 401

    decoded_payload = decode_jwt_token(token)
    if "error" in decoded_payload:
        return decoded_payload, 401

    batch_number = request.get_json().get("number")
    password_list = []
    for _ in range(batch_number):
        while True:
            try:
                password = random_password_generator(14)
                break
            except ValueError:
                continue
        
        password_breach_checking = haveibeenpwnd_checking(password)
        if password_breach_checking:
            secure_password_generator()
        else:
            password_list.append(password)

    return {"Password List": password_list}



@app.route('/api/secure_password_generator', methods=['GET'])
def secure_password_generator():
    # Authentication with JWT token required
    token = request.headers.get("Authorization")
    if not token:
        return {"error": "Authorization token required."}, 401

    decoded_payload = decode_jwt_token(token)
    if "error" in decoded_payload:
        return decoded_payload, 401
    
    while True:
        try:
            password = random_password_generator(14)
            break  # Break the loop if no ValueError occurs
        except ValueError:
            # If ValueError occurs, generate a new password
            password = secure_password_generator()

    password_breach_checking = haveibeenpwnd_checking(password)
    if password_breach_checking:
        secure_password_generator()
    else:
        return {'message': password}

@app.route('/api/secure_password_checker', methods=['POST'])
def secure_password_checker(password=None, token=None):
    if request.headers.get("Authorization") is not None:
        # Authentication with JWT token required
        token = request.headers.get("Authorization")
    if not token:
        return {"error": "Authorization token required."}, 401

    decoded_payload = decode_jwt_token(token)
    if "error" in decoded_payload:
        return decoded_payload, 401

    data = request.get_json()
    password = data.get("password")

    password_breach_checking = haveibeenpwnd_checking(password)
    if password_breach_checking:
        return {'message': "You're password is breached before."}
    else:
        return {'message': checking_password_security(password)}
    

if __name__ == '__main__':
    app.run(debug=True)


# sqp_15acbb780c7061f577dc5b71771b88791c65bfe3
# B0tiRSyBj2LlsAA8 LwroO77y9F0IidA5
# mongodb+srv://<username>:<password>@pms.srvkhxr.mongodb.net/?retryWrites=true&w=majority
# mongodb+srv://<username>:<password>@pms.srvkhxr.mongodb.net/

# sonar-scanner \
#   -Dsonar.projectKey=pms \
#   -Dsonar.sources=. \
#   -Dsonar.host.url=http://127.0.0.1:9000 \
#   -Dsonar.token=sqp_15acbb780c7061f577dc5b71771b88791c65bfe3
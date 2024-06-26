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
    
    """
    Function to check if the password has been pwned.

    :param password: Password to check
    :return: True if pwned, False otherwise
    """
    
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
    
    """
    Function to hash the password using SHA-256.

    :param password: Password to hash
    :return: Hashed password
    """
    
    encoded_pass = password.encode('utf-8')
    
    sha256_hasher = hashlib.sha256()
    sha256_hasher.update(encoded_pass)
    
    return sha256_hasher.hexdigest()

def generate_jwt_token(username):
    
    """
    Function to generate JWT token.

    :param username: Username for the token
    :return: JWT token
    """
    
    payload = {"username": username}
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    
    return token

def decode_jwt_token(token):
    
    """
    Function to decode JWT token.

    :param token: JWT token
    :return: Decoded payload or error message
    """
    
    try:
        decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        
        return decoded_payload
        
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired."}
        
    except jwt.InvalidTokenError:
        return {"error": "Invalid token."}


def database_insertition(username, password):
    
    """
    Function to insert data into the database.

    :param username: Username to insert
    :param password: Password to insert
    """
    
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
    
    """
    Function to read data from the database.

    :param username: Username to read
    :param password: Password to read
    :return: True if user exists, False otherwise
    """
    
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
    
    """
    Function to check the security of a password.

    :param password: Password to check
    :return: Security check result
    """
    
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
    
    """
    Function to generate a random password.

    :param length: Length of the password
    :return: Generated password
    """
    
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
    
    """
    API endpoint to update policy.

    :return: Update result
    """
    
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
    
    """
    API endpoint to login.

    :return: Login result
    """
    
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
    
    """
    API endpoint to create a user.

    :return: User creation result
    """
    
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
    
    """
    API endpoint for batch password generation.

    :return: Generated password list
    """
    
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
    
    """
    API endpoint for secure password generation.

    :return: Generated secure password
    """
    
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
    
    """
    API endpoint to check the security of a password.

    :return: Security check result
    """
    
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


# Amroz Code

@app.route('/api/execute_secure', methods=['POST'])
def execute_secure_command():
    data = request.get_json()
    command = data.get("command")

    # List of allowed commands
    allowed_commands = {
        'ls': 'ls',
        'pwd': 'pwd',
        'whoami': 'whoami',
        'date': 'date',
        'uptime': 'uptime',
        'df': 'df -h',
        'ping': 'ping -c 4 google.com'  # example: ping google.com 4 times

    }


    # Validate the command
    if command not in allowed_commands:
        return jsonify({"message": "Invalid command"}), 400

    # Execute the command safely
    try:
        result = subprocess.run(allowed_commands[command], shell=True, capture_output=True, text=True)
        return jsonify({"message": "Command executed", "result": result.stdout})
    except Exception as e:
        return jsonify({"message": "Error executing command", "error": str(e)}), 500

#Vulnerability ////////////////////////////////////////////////////////////////////////////////

@app.route('/api/execute_insecure', methods=['POST'])
def execute_command():
    data = request.get_json()
    command = data.get("command")

    # Execute the command and capture the output
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return jsonify({"message": "Command executed", "result": result.stdout})
    except Exception as e:
        return jsonify({"message": "Error executing command", "error": str(e)}), 500


def database_reading_unsave(user_input):
    mongo_uri = "mongodb://localhost:27017"
    client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)
    db = client["pms"]
    collection = db["pms"]

    # Introduce a vulnerability by using user input directly in the query
    query = user_input
    cursor = collection.find(query)

    for document in cursor:
        if document.get('username'):
            return True
    return False

#Cross-site Scripting //////////////////////////////////////////////////////////////////

@app.route('/api/xss_vulnerable', methods=['POST'])
def xss_vulnerable():
    data = request.get_json()
    username = data.get("username")

    # Display the username directly in the response
    return f"Hello, {username}!"

"""
An attacker can send request with below payload: 

{
    "username": "<script>alert('XSS')</script>"
}

Response would be like this:
Hello, <script>alert('XSS')</script>! 

"""
# Script XSS vulnerability mitigation ////////////////////////////////////////

from markupsafe import escape

@app.route('/api/xss_vulnerable_mitigation', methods=['POST'])
def xss_vulnerable_mitigation():
    data = request.get_json()
    username = data.get("username")

    # Escape the username to prevent XSS
    safe_username = escape(username)

    # Display the escaped username in the response
    return f"Hello, {safe_username}!"



#Insecure Direct Object Reference //////////////////////////////////////////////////////
from bson.objectid import ObjectId

@app.route('/api/get_user_data', methods=['GET'])
def get_user_data():
    user_id = request.args.get("user_id")

    # Debug print for the user_id received
    print(f"Received user_id: {user_id}")

    # Validate the user_id format
    if not user_id or not re.match(r"^[0-9a-fA-F]{24}$", user_id):
        print("Invalid user_id format")
        return jsonify({"message": "Invalid user_id format"}), 400

    try:
        # Connect to MongoDB
        mongo_uri = "mongodb://localhost:27017"
        client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)
        db = client["pms"]
        collection = db["pms"]

        # Print the user_id to ensure it's correct
        print(f"Querying for user_id: {user_id}")

        # Convert user_id to ObjectId
        object_id = ObjectId(user_id)
        print(f"Converted ObjectId: {object_id}")

        # Find the user
        user = collection.find_one({"_id": object_id})

        # Print the user data if found
        if user:
            print(f"User found: {user}")
            user["_id"] = str(user["_id"])  # Convert ObjectId to string for JSON serialization
            return jsonify(user)
        else:
            print("User not found")
            return jsonify({"message": "User not found"}), 404
    except pymongo.errors.PyMongoError as e:
        print(f"Database error: {e}")
        return jsonify({"message": "Database error", "error": str(e)}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"message": "Unexpected error", "error": str(e)}), 500



#Feature ////////////////////////////////////////////////////////////////////////

def password_strength_feedback(password):

    data = request.get_json()
    password = data.get("password")

    feedback = []
    if len(password) < 12:
        feedback.append("Password should be at least 12 characters long.")
    if not re.search("[A-Z]", password):
        feedback.append("Password should include at least one uppercase letter.")
    if not re.search("[a-z]", password):
        feedback.append("Password should include at least one lowercase letter.")
    if not re.search("[0-9]", password):
        feedback.append("Password should include at least one number.")
    if not re.search("[^A-Za-z0-9]", password):
        feedback.append("Password should include at least one special character.")
    if not feedback:
        feedback.append("Password is strong.")
    return feedback

@app.route('/api/password_strength', methods=['POST'])
def password_strength():
    data = request.get_json()
    password = data.get("password")
    feedback = password_strength_feedback(password)
    return {"feedback": feedback}

# End of Amroz Code



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

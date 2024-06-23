def database_insertition(username, password):
    mongo_uri = "mongodb://localhost:27017"# "mongodb+srv://dharmikpatel08:RoeDKw9EC5T4p4dQ@pms.kzqukrf.mongodb.net/?retryWrites=true&w=majority"
    client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)

    # Access a specific database
    db = client["pms"]

    # Define a sample document
    content = {
        "username": username,
        "password": sha256_hashing(password),
        "failed_attempts": 0
    }

    # Insert the document into a collection
    collection = db["pms"]
    result = collection.insert_one(content)

    # Print the inserted document's ID
    # print(f"Inserted document ID: {result.inserted_id}")
def reset_failed_attempts(username):
    mongo_uri = "mongodb://localhost:27017"
    client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)
    db = client["pms"]
    collection = db["pms"]
    collection.update_one({"username": username}, {"$set": {"failed_attempts": 0, "lockout": False}})

@app.route('/api/login', methods=['POST'])


def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    mongo_uri = "mongodb://localhost:27017"
    client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)
    db = client["pms"]
    with db_lock:
        user = db.pms.find_one({"username": username})
        if user:
            if user.get("lockout"):
                return {"message": "Account is locked due to too many failed login attempts. Please reset your password or contact support."}, 403
            checking_login = database_reading(username, password)
            if checking_login:
                reset_failed_attempts(username)
                token = generate_jwt_token({"username": username})
                return {"message": "Login Successful", "token": token}
            else:
                db.pms.update_one({"username": username}, {"$inc": {"failed_attempts": 1}})
                user = db.pms.find_one({"username": username})
                if user["failed_attempts"] == 2:
                    return {"message": "Warning: One more unsuccessful attempt will lock your account."}, 401
                elif user["failed_attempts"] >= 3:
                    db.pms.update_one({"username": username}, {"$set": {"lockout": True}})
                    return {"message": "Account is locked due to too many failed login attempts. Please reset your password or contact support."}, 403
                return {"message": "Login Failed"}, 401
        else:
            return {"message": "User not found"}, 404

def find_user_by_username(username):
    mongo_uri = "mongodb://localhost:27017"
    client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)
    
    db = client["pms"]
    collection = db["pms"]
    
    user = collection.find_one({"username": username})
    print(f"find_user_by_username: Searching for username '{username}' resulted in {user}")
    return user

@app.route('/api/delete_account', methods=['DELETE'])
def delete_account():
    data = request.get_json()
    username = data.get("username")
    print(f"delete_account: Received request to delete username '{username}'")

    with db_lock:
        print(f"delete_account: Acquired DB lock for username '{username}'")
        user = find_user_by_username(username)
        if user:
            print(f"delete_account: User found: {user}")
            mongo_uri = "mongodb://localhost:27017"
            client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)
            db = client["pms"]
            collection = db["pms"]
            result = collection.delete_one({"username": username})
            if result.deleted_count == 1:
                print("delete_account: Account deleted successfully.")
                return {"message": "Account deleted successfully."}
            else:
                print("delete_account: Account deletion failed.")
                return {"error": "Account deletion failed."}, 500
        else:
            print("delete_account: User not found.")
            return {"error": "User not found."}, 404
        
@app.route('/api/update_password', methods=['POST'])
def update_password():
    token = request.headers.get("Authorization")
    if not token:
        return {"error": "Authorization token required."}, 401

    decoded_payload = decode_jwt_token(token)
    if "error" in decoded_payload:
        return decoded_payload, 401

    username = decoded_payload["username"]
    data = request.get_json()
    current_password = data.get("current_password")
    new_password = data.get("new_password")

    mongo_uri = "mongodb://localhost:27017"
    client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)
    db = client["pms"]
    collection = db["pms"]

    with db_lock:
        user = collection.find_one({"username": username})
        if user and user["password"] == sha256_hashing(current_password):
            hashed_password = sha256_hashing(new_password)
            result = collection.update_one({"username": username}, {"$set": {"password": hashed_password}})
            if result.modified_count == 1:
                return {"message": "Password updated successfully."}
            else:
                return {"error": "Password update failed."}, 500
        else:
            return {"error": "Current password is incorrect."}, 401
        

@app.route('/api/update_username', methods=['POST'])
def update_username():
    token = request.headers.get("Authorization")
    if not token:
        return {"error": "Authorization token required."}, 401

    decoded_payload = decode_jwt_token(token)
    if "error" in decoded_payload:
        return decoded_payload, 401

    current_username = decoded_payload["username"]
    data = request.get_json()
    current_password = data.get("current_password")
    new_username = data.get("new_username")

    mongo_uri = "mongodb://localhost:27017"
    client = pymongo.MongoClient(mongo_uri, tlsAllowInvalidCertificates=True)
    db = client["pms"]
    collection = db["pms"]

    with db_lock:
        user = collection.find_one({"username": current_username})
        print(f"Current username: {current_username}")
        print(f"User found: {user}")
        if user:
            stored_password_hash = user["password"]
            provided_password_hash = sha256_hashing(current_password)
            print(f"Stored password hash: {stored_password_hash}")
            print(f"Provided password hash: {provided_password_hash}")
            if stored_password_hash == provided_password_hash:
                result = collection.update_one({"username": current_username}, {"$set": {"username": new_username}})
                if result.modified_count == 1:
                    # Update the JWT token with the new username
                    token = generate_jwt_token({"username": new_username})
                    return {"message": "Username updated successfully.", "token": token}
                else:
                    return {"error": "Username update failed."}, 500
            else:
                return {"error": "Current password is incorrect."}, 401
        else:
            return {"error": "User not found."}, 404

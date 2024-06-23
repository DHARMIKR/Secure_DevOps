import pms , app
import subprocess
from flask import Flask, request, jsonify
from datetime import datetime
import hashlib
import requests
import pymongo
import json
import threading
import jwt
import secrets
import re
import string
import os
#Vulnerability mitigation: ///////////////////////////////////////////////////////////////

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


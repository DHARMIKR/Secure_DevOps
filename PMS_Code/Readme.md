# Steps to make it run.

### First install all the dependencies using pip.
### Make sure you install "pyjwt" and not "jwt" library using pip. Otherwise, it will give errors.
### Install the docker in the system if not already.
### Install Mongo container in docker.
  - docker pull mongo
  - docker run --name mongodb -d -p 27017:27017 mongo
### Download Mongo Compass GUI version [https://www.mongodb.com/try/download/compass]. It will help to see the tables and users added into database.
### Connect the mongodb using Mongo Compass GUI.
### Run the code.


# APIs of the code.

### /api/policy_update [For updating policy] [POST request] [have to give Authorization token in the header which you will get after signup or login] [And have to give new policy in the body]
### /api/login [For login and getting Authorization token] [POST request] [Send username and password in the body]
### /api/user_creation [For signup] [POST request] [Send username and password in the body]
### /api/batch_password_generation [For generating batch passwords] [POST request] [Send authorization token in the header] [And give the number of passwords you want to generate in the body]
### /api/secure_password_generator [For generating a single password] [GET request] [Send authorization token in the header]
### /api/secure_password_checker [For checking the security of a give password] [POST request] [Send authorization token in the header] [And give password in the body]


# Things we can add

### Multi Factor Authentication [MFA]
### Audit Logs and Monitoring
### API Rate Limiting and Throttling
### Forget Password Feature


# Functionality with Vulnerabilities

#### Signup - SQL Injection, Weak Password Policy
#### Login - Brute Force Attacks, SQL Injection
#### Policy Update - Unauthorized Access, Insufficient Input Validation
#### Secure Password Generator - Predictable Password Generation
#### Secure Password Checker - Insecure Transmission of Passwords, Command Injection
#### Batch Password Generator - Rate Limiting
#### JWT Tokens - All JWT related vulnerabilities
#### MFA - Bypass MFA
#### Audit Logs - Log Tampering
#### Forget Password - Flawed Logic of the feature

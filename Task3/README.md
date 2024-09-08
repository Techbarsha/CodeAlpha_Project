# Secure Coding Review

## Overview

This project involves a secure coding review of a Python application. The primary goal was to identify and mitigate critical security vulnerabilities, such as SQL injection and plaintext password storage. The review process included static code analysis and manual code review to ensure the application adheres to secure coding practices.

## Features

- **Password Hashing**: Utilizes `bcrypt` for securely hashing and salting passwords.
- **SQL Injection Prevention**: Implements parameterized queries to protect against SQL injection attacks.
- **Static Code Analysis**: Uses `Bandit` to automatically detect security issues in the code.
- **Manual Code Review**: Involves a detailed step-by-step code review to identify vulnerabilities and propose secure solutions.

## Technologies Used

- **Python**: Main programming language for the application.
- **SQLite**: Lightweight database used for storing user credentials.
- **bcrypt**: Library for secure password hashing.
- **Bandit**: Static code analyzer for detecting security vulnerabilities.

## Dependencies

To ensure that the application runs smoothly, install the following dependencies:

- `bcrypt`: For password hashing
- `bandit`: For static code analysis
- `sqlite3`: For the database (comes pre-installed with Python)

You can install the required Python libraries using `pip`:

```bash
pip install bcrypt bandit

# How to Run
# Follow these steps to run the secure coding review application:

# Clone the Repository:

## Clone the repository to your local machine using the following command:
```
git clone [REPOSITORY_URL]
```
## Navigate to the project directory:
```
cd [REPOSITORY_DIRECTORY]
```
## Install Dependencies:
## Install the necessary Python libraries specified in the requirements.txt file:
```
pip install -r requirements.txt
```
## Run the Application: Execute the Python script to start the application and perform the secure coding review
```
python secure_login.py
```
## Run Bandit Analysis:Perform static code analysis with Bandit to detect security vulnerabilities
```
bandit -r secure_login.py
```
## Review Bandit Results:
- **Examine the Bandit output for identified security issues and recommendations. This will include a report detailing any vulnerabilities found and suggested fixes.**

##Testing and Verification:
- **Ensure the application behaves as expected by registering new users and logging in with the hashed passwords.**
- **Verify that all security recommendations have been applied and that no new vulnerabilities are present.**

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements
- **Bandit: For automated security analysis.**
- **bcrypt: For password hashing and security.**
- **Python Community: For providing a robust and versatile programming language.**

from flask import Flask, request, redirect, render_template_string, session
import sqlite3
import pickle
import os
import subprocess
import xml.etree.ElementTree as ET
import yaml

app = Flask(__name__)
app.secret_key = "super_secret_key_123"  # Hard-coded secret key

# Unsafe database connection
def get_db():
    return sqlite3.connect('users.db')

# SQL Injection vulnerability
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    conn = get_db()
    cursor = conn.cursor()
    result = cursor.execute(query).fetchone()
    
    if result:
        session['username'] = username
        return redirect('/dashboard')
    return "Login failed"

# Command Injection vulnerability
@app.route('/ping', methods=['POST'])
def ping_host():
    hostname = request.form['hostname']
    # Dangerous command execution
    output = subprocess.check_output(f"ping -c 1 {hostname}", shell=True)
    return output.decode()

# Unsafe deserialization
@app.route('/load_config', methods=['POST'])
def load_config():
    config_data = request.form['config']
    # Dangerous deserialization
    config = pickle.loads(config_data.encode())
    return str(config)

# Path Traversal vulnerability
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    # Dangerous file access
    with open(filename, 'r') as f:
        return f.read()

# XML External Entity (XXE) vulnerability
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.form['xml']
    # Vulnerable XML parsing
    tree = ET.fromstring(xml_data)
    return tree.find('data').text

# YAML deserialization vulnerability
@app.route('/parse_yaml', methods=['POST'])
def parse_yaml():
    yaml_data = request.form['yaml']
    # Unsafe YAML parsing
    parsed_data = yaml.load(yaml_data)
    return str(parsed_data)

# Cross-Site Scripting (XSS) vulnerability
@app.route('/profile')
def profile():
    username = request.args.get('user', '')
    # Unsafe template
    template = f'''
    <h1>Welcome {username}!</h1>
    <p>This is your profile page.</p>
    '''
    return render_template_string(template)

# Insecure file upload
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file uploaded'
    file = request.files['file']
    # Dangerous file save without validation
    file.save(os.path.join('uploads', file.filename))
    return 'File uploaded successfully'

# Information disclosure through error messages
@app.route('/user/<int:user_id>')
def get_user(user_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise Exception("User not found in database!")
    except Exception as e:
        # Unsafe error disclosure
        return str(e), 500

# Hard-coded credentials
DATABASE_USER = "admin"
DATABASE_PASS = "admin123"

# Insecure direct object reference
@app.route('/document/<doc_id>')
def get_document(doc_id):
    # No access control
    return open(f"documents/{doc_id}.txt").read()

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode enabled in production
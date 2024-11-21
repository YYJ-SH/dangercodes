from flask import Flask, request, redirect, render_template_string, session
import sqlite3
import pickle
import os
import subprocess
import xml.etree.ElementTree as ET
import yaml

app = Flask(__name__)
app.secret_key = "super_secret_key_123"

def get_db():
    return sqlite3.connect('users.db')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = get_db()
    cursor = conn.cursor()
    result = cursor.execute(query).fetchone()
    if result:
        session['username'] = username
        return redirect('/dashboard')
    return "Login failed"

@app.route('/ping', methods=['POST'])
def ping_host():
    hostname = request.form['hostname']
    output = subprocess.check_output(f"ping -c 1 {hostname}", shell=True)
    return output.decode()

@app.route('/load_config', methods=['POST'])
def load_config():
    config_data = request.form['config']
    config = pickle.loads(config_data.encode())
    return str(config)

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    with open(filename, 'r') as f:
        return f.read()

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.form['xml']
    tree = ET.fromstring(xml_data)
    return tree.find('data').text

@app.route('/parse_yaml', methods=['POST'])
def parse_yaml():
    yaml_data = request.form['yaml']
    parsed_data = yaml.load(yaml_data)
    return str(parsed_data)

@app.route('/profile')
def profile():
    username = request.args.get('user', '')
    template = f'''
    <h1>Welcome {username}!</h1>
    <p>This is your profile page.</p>
    '''
    return render_template_string(template)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file uploaded'
    file = request.files['file']
    file.save(os.path.join('uploads', file.filename))
    return 'File uploaded successfully'

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
        return str(e), 500

DATABASE_USER = "admin"
DATABASE_PASS = "admin123"

@app.route('/document/<doc_id>')
def get_document(doc_id):
    return open(f"documents/{doc_id}.txt").read()

if __name__ == '__main__':
    app.run(debug=True)
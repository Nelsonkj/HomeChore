import json
import os
from datetime import datetime
from uuid import uuid4
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from functools import wraps
import bcrypt

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure random key

# Files
TASK_FILE = "tasks.json"
ORDER_FILE = "order.json"
USERS_FILE = "users.json"

# ----------------------------------
# User management helpers
# ----------------------------------

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def hash_password(plain):
    return bcrypt.hashpw(plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(plain, hashed):
    try:
        return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))
    except:
        return False

def user_exists(username):
    users = load_users()
    return username.lower() in users

def get_user(username):
    users = load_users()
    return users.get(username.lower())

# ----------------------------------
# Auth decorators & helpers
# ----------------------------------

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return wrapped

def current_user():
    return session.get('username')

def current_role():
    return session.get('role')

# ----------------------------------
# Initialize users file with admin if empty
# ----------------------------------

def init_users_file():
    if not os.path.exists(USERS_FILE):
        # Default admin user (change password immediately)
        default_admin = {
            "josh": {
                "password": hash_password("moneydaddy"),
                "role": "admin"
            }
        }
        save_users(default_admin)

init_users_file()

# ----------------------------------
# Routes: Login / Logout
# ----------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form.get('username', '').lower()
        pwd = request.form.get('password', '')
        user = get_user(uname)
        if user and check_password(pwd, user['password']):
            session['username'] = uname
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_HTML, error="Invalid username or password")
    return render_template_string(LOGIN_HTML, error=None)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

# ----------------------------------
# Dashboard route
# ----------------------------------

@app.route('/')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML, username=current_user(), role=current_role())

# ----------------------------------
# API: User management (admin only)
# ----------------------------------

@app.route('/api/users', methods=['GET'])
@login_required
@admin_required
def list_users():
    users = load_users()
    # Don't send password hashes to frontend
    safe_users = [{ "username": u, "role": v["role"] } for u,v in users.items()]
    return jsonify(safe_users)

@app.route('/api/users', methods=['POST'])
@login_required
@admin_required
def add_user():
    data = request.json
    username = data.get("username", "").lower()
    password = data.get("password", "")
    role = data.get("role", "member")
    if not username or not password or role not in ["admin", "member"]:
        return jsonify({"error": "Invalid user data"}), 400
    users = load_users()
    if username in users:
        return jsonify({"error": "User already exists"}), 400
    users[username] = {
        "password": hash_password(password),
        "role": role
    }
    save_users(users)
    return jsonify({"message": "User added"}), 201

@app.route('/api/users/<username>', methods=['PUT'])
@login_required
@admin_required
def edit_user(username):
    username = username.lower()
    data = request.json
    users = load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    if 'password' in data and data['password']:
        users[username]['password'] = hash_password(data['password'])
    if 'role' in data and data['role'] in ['admin', 'member']:
        users[username]['role'] = data['role']
    save_users(users)
    return jsonify({"message": "User updated"})

@app.route('/api/users/<username>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(username):
    username = username.lower()
    if username == current_user():
        return jsonify({"error": "Cannot delete yourself"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    users.pop(username)
    save_users(users)
    return jsonify({"message": "User deleted"})

# ----------------------------------
# --- Existing task APIs below ---
# Add @login_required decorators to existing APIs as needed
# ----------------------------------

# ... [Your existing task APIs with @login_required] ...
# (To save space, reuse your existing task-related routes from your app with login_required added)

# ----------------------------------
# HTML templates with User Management UI
# ----------------------------------

LOGIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login - HomeChores</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 2rem; }
      label { display: block; margin-top: 1rem; }
      input { padding: 0.5rem; width: 100%; }
      button { margin-top: 1rem; padding: 0.5rem 1rem; }
      .error { color: red; margin-top: 1rem; }
    </style>
</head>
<body>
    <h1>Login to HomeChores</h1>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST">
        <label>Username: <input name="username" required autofocus></label>
        <label>Password: <input type="password" name="password" required></label>
        <button type="submit">Log In</button>
    </form>
</body>
</html>
'''

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - HomeChores</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family: Arial, sans-serif; margin: 1rem; }
      .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
      button { padding: 0.4rem 0.8rem; cursor: pointer; }
      #welcome { font-weight: bold; }
      #logout { background: #e74c3c; color: white; border: none; border-radius: 4px; }
      #logout:hover { background: #c0392b; }
      #userMgmtBtn { background: #3498db; color: white; border: none; border-radius: 4px; margin-left: 1rem; }
      #userMgmtBtn:hover { background: #2980b9; }
      #taskManager, #userManager { margin-top: 1rem; }
      #userManager { display: none; }
      table { width: 100%; border-collapse: collapse; }
      th, td { padding: 0.5rem; border: 1px solid #ddd; }
      th { background-color: #f2f2f2; }
      input, select { width: 100%; padding: 0.3rem; }
      .error { color: red; margin-top: 0.5rem; }
    </style>
</head>
<body>
    <div class="top-bar">
      <div id="welcome">Welcome, {{ username }} ({{ role }})</div>
      <div>
        <button id="logout">Log Out</button>
        {% if role == 'admin' %}
        <button id="userMgmtBtn">User Management</button>
        {% endif %}
      </div>
    </div>

    <div id="taskManager">
      <p>Loading your task manager UI...</p>
    </div>

    {% if role == 'admin' %}
    <div id="userManager">
      <h2>User Management</h2>
      <button onclick="showAddUser()">Add User</button>
      <table id="userTable">
        <thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead>
        <tbody></tbody>
      </table>
      <div id="userForm" style="display:none; margin-top:1rem;">
        <h3 id="userFormTitle">Add User</h3>
        <label>Username: <input id="usernameInput"></label>
        <label>Password: <input type="password" id="passwordInput"></label>
        <label>Role: 
          <select id="roleSelect">
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
        </label>
        <button onclick="submitUser()">Submit</button>
        <button onclick="cancelUser()">Cancel</button>
        <div class="error" id="userFormError"></div>
      </div>
    </div>
    {% endif %}

<script>
// Logout
document.getElementById('logout').onclick = () => {
  window.location.href = '/logout';
};

{% if role == 'admin' %}
// User management UI
const userManagerDiv = document.getElementById('userManager');
const userTableBody = document.querySelector('#userTable tbody');
const userFormDiv = document.getElementById('userForm');
const userFormTitle = document.getElementById('userFormTitle');
const usernameInput = document.getElementById('usernameInput');
const passwordInput = document.getElementById('passwordInput');
const roleSelect = document.getElementById('roleSelect');
const userFormError = document.getElementById('userFormError');

let editingUser = null;

document.getElementById('userMgmtBtn').onclick = () => {
  if(userManagerDiv.style.display === 'none'){
    userManagerDiv.style.display = 'block';
    loadUsers();
  } else {
    userManagerDiv.style.display = 'none';
    userFormDiv.style.display = 'none';
  }
};

function loadUsers(){
  fetch('/api/users')
    .then(res => res.json())
    .then(users => {
      userTableBody.innerHTML = '';
      users.forEach(u => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${u.username}</td>
          <td>${u.role}</td>
          <td>
            <button onclick="editUser('${u.username}')">Edit</button>
            <button onclick="deleteUser('${u.username}')">Delete</button>
          </td>`;
        userTableBody.appendChild(tr);
      });
    });
}

function showAddUser(){
  editingUser = null;
  userFormTitle.textContent = 'Add User';
  usernameInput.value = '';
  passwordInput.value = '';
  roleSelect.value = 'member';
  userFormError.textContent = '';
  userFormDiv.style.display = 'block';
}

function editUser(username){
  editingUser = username;
  userFormTitle.textContent = `Edit User: ${username}`;
  userFormError.textContent = '';
  fetch(`/api/users/${username}`)
    .then(res => {
      if(res.ok) return res.json();
      throw new Error('User not found');
    })
    .then(user => {
      usernameInput.value = username;
      usernameInput.disabled = true;
      passwordInput.value = '';
      roleSelect.value = user.role;
      userFormDiv.style.display = 'block';
    })
    .catch(err => {
      alert(err.message);
    });
}

function cancelUser(){
  userFormDiv.style.display = 'none';
  usernameInput.disabled = false;
}

function submitUser(){
  const username = usernameInput.value.trim().toLowerCase();
  const password = passwordInput.value;
  const role = roleSelect.value;

  if(!username) {
    userFormError.textContent = 'Username required';
    return;
  }
  if(!editingUser && !password){
    userFormError.textContent = 'Password required for new user';
    return;
  }

  userFormError.textContent = '';
  const method = editingUser ? 'PUT' : 'POST';
  const url = editingUser ? `/api/users/${editingUser}` : '/api/users';
  const body = editingUser ? { role } : { username, password, role };

  fetch(url, {
    method,
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  }).then(res => {
    if(res.ok) {
      userFormDiv.style.display = 'none';
      usernameInput.disabled = false;
      loadUsers();
    } else {
      res.json().then(data => {
        userFormError.textContent = data.error || 'Failed to save user';
      });
    }
  });
}

function deleteUser(username){
  if(!confirm(`Delete user '${username}'?`)) return;
  if(username === '{{ username }}'){
    alert("You can't delete yourself!");
    return;
  }
  fetch(`/api/users/${username}`, {method: 'DELETE'})
    .then(res => {
      if(res.ok) loadUsers();
      else res.json().then(data => alert(data.error || 'Failed to delete user'));
    });
}
{% endif %}
</script>
'''

# ----------------------------------
# Main app runner
# ----------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4545)

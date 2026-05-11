# ============================================================
# TaskManager API — DevSecOps Simulation Application
# ============================================================
# This is a simple Flask REST API for managing tasks.
# It connects to a SQLite database to store tasks.
#
# IMPORTANT: This app has INTENTIONAL security weaknesses.
# They are here so our security tools have real findings to catch.
# We will identify and fix them as we go through the sessions.
# ============================================================

from flask import Flask, request, jsonify
import sqlite3
import os

# ---- App Setup ----
# Flask is the web framework. We create an instance of it here.
app = Flask(__name__)

# !! SECURITY WEAKNESS 1: Hardcoded secret key !!
# A secret key should NEVER be hardcoded in source code.
# It should be loaded from an environment variable or secrets manager.
# Our secret scanning tool (detect-secrets) will catch this in Session 2.
app.config['SECRET_KEY'] = 'hardcoded-secret-key-123'

# ---- Database Setup ----
# We use SQLite — a simple file-based database.
# The database file will be created automatically on first run.
DATABASE = 'taskmanager.db'


def get_db():
    """
    Opens a connection to the SQLite database.
    This function is called every time we need to talk to the database.
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # This lets us access columns by name
    return conn


def init_db():
    """
    Creates the tasks table if it doesn't exist yet.
    This runs once when the app starts.
    """
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            created_by TEXT
        )
    ''')
    conn.commit()
    conn.close()


# ---- API Routes ----
# Routes are the URLs our API responds to.
# Each route has a function that runs when that URL is called.

@app.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint.
    Returns 'ok' so we know the app is running.
    Used by monitoring systems and DAST tools to confirm the app is alive.
    """
    return jsonify({"status": "ok", "app": "TaskManager"})


@app.route('/tasks', methods=['GET'])
def get_tasks():
    """
    GET /tasks
    Returns all tasks from the database.
    No authentication required — anyone can see all tasks.
    (This itself is a design issue we'll discuss in threat modelling)
    """
    conn = get_db()
    tasks = conn.execute('SELECT * FROM tasks').fetchall()
    conn.close()
    return jsonify([dict(task) for task in tasks])


@app.route('/tasks', methods=['POST'])
def create_task():
    """
    POST /tasks
    Creates a new task.
    Accepts JSON body: { "title": "...", "description": "...", "created_by": "..." }
    """
    data = request.get_json()

    # Basic check that title exists
    if not data or 'title' not in data:
        return jsonify({"error": "Title is required"}), 400

    title = data.get('title')
    description = data.get('description', '')
    created_by = data.get('created_by', 'anonymous')

    conn = get_db()

    # !! SECURITY WEAKNESS 2: SQL Injection vulnerability !!
    # We are directly inserting user input into a SQL query using string formatting.
    # An attacker can send a malicious title like: ' OR '1'='1
    # and manipulate the database query.
    # Our SAST tool (Semgrep) will catch this in Session 3.
    # The SAFE way is to use parameterised queries: (?, ?, ?)
    query = "INSERT INTO tasks (title, description, created_by) VALUES ('" + title + "', '" + description + "', '" + created_by + "')"
    conn.execute(query)
    conn.commit()
    conn.close()

    return jsonify({"message": "Task created successfully"}), 201


@app.route('/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    """
    GET /tasks/<id>
    Returns a single task by its ID.
    Example: GET /tasks/1 returns task with ID 1.

    !! SECURITY WEAKNESS 3: No authorisation check !!
    Any user can access any task by ID — including tasks created by others.
    This is called IDOR (Insecure Direct Object Reference).
    OWASP API Top 10 #1: Broken Object Level Authorization.
    Our DAST tool (ZAP) will probe this in Session 5.
    """
    conn = get_db()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    conn.close()

    if task is None:
        # !! SECURITY WEAKNESS 4: Verbose error message !!
        # Returning internal details in error messages helps attackers
        # understand the system structure.
        return jsonify({
            "error": "Task not found",
            "database": DATABASE,
            "query": f"SELECT * FROM tasks WHERE id = {task_id}"
        }), 404

    return jsonify(dict(task))


@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    """
    PUT /tasks/<id>
    Updates an existing task.
    Accepts JSON body with any fields to update: title, description, status.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    conn = get_db()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()

    if task is None:
        conn.close()
        return jsonify({"error": "Task not found"}), 404

    title = data.get('title', task['title'])
    description = data.get('description', task['description'])
    status = data.get('status', task['status'])

    conn.execute(
        'UPDATE tasks SET title = ?, description = ?, status = ? WHERE id = ?',
        (title, description, status, task_id)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Task updated successfully"})


@app.route('/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    """
    DELETE /tasks/<id>
    Deletes a task by its ID.
    No authentication required — anyone can delete any task.
    """
    conn = get_db()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()

    if task is None:
        conn.close()
        return jsonify({"error": "Task not found"}), 404

    conn.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "Task deleted successfully"})


@app.route('/tasks/search', methods=['GET'])
def search_tasks():
    """
    GET /tasks/search?q=<search_term>
    Searches tasks by title.
    Example: GET /tasks/search?q=meeting

    !! SECURITY WEAKNESS 5: Another SQL Injection point !!
    The search term is directly inserted into the SQL query.
    This is a classic SQL injection vulnerability.
    """
    search_term = request.args.get('q', '')

    conn = get_db()
    # Vulnerable query — search term inserted directly
    query = f"SELECT * FROM tasks WHERE title LIKE '%{search_term}%'"
    tasks = conn.execute(query).fetchall()
    conn.close()

    return jsonify([dict(task) for task in tasks])


# ---- App Entry Point ----
if __name__ == '__main__':
    init_db()  # Create the database tables on startup
    # !! Debug mode exposes detailed error pages to users in production !!
    # This should be False in production.
    app.run(debug=True, host='0.0.0.0', port=5000)

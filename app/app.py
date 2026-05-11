# ============================================================
# TaskManager API — DevSecOps Simulation Application
# ============================================================
# This is a simple Flask REST API for managing tasks.
# It connects to a SQLite database to store tasks.
#
# SECURITY FIXES APPLIED IN THIS SESSION:
# - SECRET_KEY now loaded from environment variable (was hardcoded)
# ============================================================

from flask import Flask, request, jsonify
import sqlite3
import os

# ---- App Setup ----
app = Flask(__name__)

# FIXED: Secret key now loaded from environment variable.
# If the environment variable is not set, we use a default
# for LOCAL DEVELOPMENT ONLY — never in production.
# In production, the SECRET_KEY environment variable must be set.
# Our Vault integration (Session 7) will inject this automatically.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'local-dev-only-not-for-production')

# ---- Database Setup ----
DATABASE = os.environ.get('DATABASE_PATH', 'taskmanager.db')


def get_db():
    """
    Opens a connection to the SQLite database.
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Creates the tasks table if it doesn't exist yet.
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


@app.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint.
    """
    return jsonify({"status": "ok", "app": "TaskManager"})


@app.route('/tasks', methods=['GET'])
def get_tasks():
    """
    GET /tasks — Returns all tasks.
    """
    conn = get_db()
    tasks = conn.execute('SELECT * FROM tasks').fetchall()
    conn.close()
    return jsonify([dict(task) for task in tasks])


@app.route('/tasks', methods=['POST'])
def create_task():
    """
    POST /tasks — Creates a new task.

    !! REMAINING WEAKNESS: SQL Injection !!
    Still using string concatenation in SQL query.
    Semgrep SAST will catch this in Session 3.
    """
    data = request.get_json()

    if not data or 'title' not in data:
        return jsonify({"error": "Title is required"}), 400

    title = data.get('title')
    description = data.get('description', '')
    created_by = data.get('created_by', 'anonymous')

    conn = get_db()
    # !! SQL INJECTION STILL HERE — intentional for Session 3 !!
    query = "INSERT INTO tasks (title, description, created_by) VALUES ('" + title + "', '" + description + "', '" + created_by + "')"
    conn.execute(query)
    conn.commit()
    conn.close()

    return jsonify({"message": "Task created successfully"}), 201


@app.route('/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    """
    GET /tasks/<id> — Returns a single task.

    !! REMAINING WEAKNESS: Verbose error + IDOR !!
    DAST will catch this in Session 5.
    """
    conn = get_db()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    conn.close()

    if task is None:
        return jsonify({
            "error": "Task not found",
            "database": DATABASE,
            "query": f"SELECT * FROM tasks WHERE id = {task_id}"
        }), 404

    return jsonify(dict(task))


@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    """
    PUT /tasks/<id> — Updates a task.
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
    DELETE /tasks/<id> — Deletes a task.
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
    GET /tasks/search?q=<term> — Searches tasks by title.

    !! REMAINING WEAKNESS: SQL Injection in search !!
    Semgrep SAST will catch this in Session 3.
    """
    search_term = request.args.get('q', '')

    conn = get_db()
    # !! SQL INJECTION STILL HERE — intentional for Session 3 !!
    query = f"SELECT * FROM tasks WHERE title LIKE '%{search_term}%'"
    tasks = conn.execute(query).fetchall()
    conn.close()

    return jsonify([dict(task) for task in tasks])


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)

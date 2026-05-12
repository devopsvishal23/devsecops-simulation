# ============================================================
# TaskManager API — DevSecOps Simulation Application
# ============================================================
# SECURITY FIXES APPLIED:
# Session 2: SECRET_KEY loaded from environment variable
# Session 3: SQL injection fixed with parameterised queries
# ============================================================

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# FIXED Session 2: Secret key from environment variable
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'local-dev-only-not-for-production')

# Database path from environment variable
DATABASE = os.environ.get('DATABASE_PATH', 'taskmanager.db')


def get_db():
    """Opens a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates the tasks table if it does not exist."""
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
    """Health check endpoint."""
    return jsonify({"status": "ok", "app": "TaskManager"})


@app.route('/tasks', methods=['GET'])
def get_tasks():
    """GET /tasks — Returns all tasks."""
    conn = get_db()
    tasks = conn.execute('SELECT * FROM tasks').fetchall()
    conn.close()
    return jsonify([dict(task) for task in tasks])


@app.route('/tasks', methods=['POST'])
def create_task():
    """
    POST /tasks — Creates a new task.

    FIXED Session 3: Parameterised query prevents SQL injection.
    User input is passed as a tuple (?, ?, ?) — the database
    driver escapes it safely. Attacker cannot break out of the
    value field into SQL command territory.
    """
    data = request.get_json()

    if not data or 'title' not in data:
        return jsonify({"error": "Title is required"}), 400

    title = data.get('title')
    description = data.get('description', '')
    created_by = data.get('created_by', 'anonymous')

    # Input validation — reject suspiciously long inputs
    if len(title) > 200:
        return jsonify({"error": "Title too long"}), 400

    conn = get_db()

    # FIXED: Parameterised query — ? placeholders, values passed separately
    # The database driver escapes all values automatically
    # An attacker sending malicious SQL in title just gets it stored as text
    conn.execute(
        'INSERT INTO tasks (title, description, created_by) VALUES (?, ?, ?)',
        (title, description, created_by)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Task created successfully"}), 201


@app.route('/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    """
    GET /tasks/<id> — Returns a single task.

    REMAINING WEAKNESS: Verbose error message exposes internals.
    DAST will find this in Session 5.
    """
    conn = get_db()
    task = conn.execute(
        'SELECT * FROM tasks WHERE id = ?', (task_id,)
    ).fetchone()
    conn.close()

    if task is None:
        # !! Still exposes database path — intentional for Session 5 !!
        return jsonify({
            "error": "Task not found",
            "database": DATABASE,
            "hint": "Check the task ID and try again"
        }), 404

    return jsonify(dict(task))


@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    """PUT /tasks/<id> — Updates a task."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    conn = get_db()
    task = conn.execute(
        'SELECT * FROM tasks WHERE id = ?', (task_id,)
    ).fetchone()

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
    """DELETE /tasks/<id> — Deletes a task."""
    conn = get_db()
    task = conn.execute(
        'SELECT * FROM tasks WHERE id = ?', (task_id,)
    ).fetchone()

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

    FIXED Session 3: Parameterised LIKE query.
    The % wildcards are added to the parameter value,
    not concatenated into the SQL string.
    """
    search_term = request.args.get('q', '')

    # Input validation
    if len(search_term) > 100:
        return jsonify({"error": "Search term too long"}), 400

    conn = get_db()

    # FIXED: Parameter contains the wildcards, SQL string is static
    # Safe: the search_term value cannot affect SQL structure
    tasks = conn.execute(
        'SELECT * FROM tasks WHERE title LIKE ?',
        (f'%{search_term}%',)
    ).fetchall()
    conn.close()

    return jsonify([dict(task) for task in tasks])


if __name__ == '__main__':
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true", host=os.environ.get("FLASK_HOST", "127.0.0.1"), port=int(os.environ.get("FLASK_PORT", "5000")))

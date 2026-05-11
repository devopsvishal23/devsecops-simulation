# ============================================================
# Basic tests for the TaskManager API
# ============================================================
# These tests verify that the API endpoints work correctly.
# We use pytest — the most popular Python testing framework.

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from app import app, init_db


@pytest.fixture
def client():
    """
    Creates a test client for our Flask app.
    This lets us make HTTP requests to the app without running a real server.
    """
    app.config['TESTING'] = True
    app.config['DATABASE'] = ':memory:'  # Use in-memory database for tests

    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client


def test_health_check(client):
    """Test that the health endpoint returns ok."""
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'ok'


def test_get_tasks_empty(client):
    """Test that getting tasks on empty database returns empty list."""
    response = client.get('/tasks')
    assert response.status_code == 200
    assert response.get_json() == []


def test_create_task(client):
    """Test that we can create a task."""
    response = client.post('/tasks', json={
        "title": "Test Task",
        "description": "This is a test task",
        "created_by": "tester"
    })
    assert response.status_code == 201


def test_create_task_without_title(client):
    """Test that creating a task without a title returns 400."""
    response = client.post('/tasks', json={"description": "No title"})
    assert response.status_code == 400

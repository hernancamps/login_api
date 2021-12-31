from flask.testing import FlaskClient
import pytest

from api import create_app


@pytest.fixture
def client():
    app = create_app("test_db.json", True)
    with app.test_client() as client:
        
        rv = client.post("/register", 
            json={"username":"test_username","password":"Pass1234@", "email": "test@email.com"})
        client.get("/verifyEmail?username=test_username&token={token}".format(token=rv.get_data().decode()))
        yield client


def test_register_user(client):
    rv = client.post("/register", 
            json={"username":"test_username_2","password":"Pass1234@", "email": "test_2@email.com"})
    assert rv.status_code == 201

def test_login_token_token_validation(client):
    rv = client.post("/login", 
            json={"username":"test_username","password":"Pass1234@"})
    assert rv.status_code == 200
    rv_2 = client.post("/puedoPasar?username=test_username", data=rv.get_data())
    assert rv_2.get_data() == b"true"


def test_register_duplicated_username(client):
    rv = client.post("/register", 
            json={"username":"test_username","password":"Pass1234@", "email": "test_2@email.com"})
    assert rv.status_code == 409


def test_register_duplicated_mail(client):
    rv = client.post("/register", 
            json={"username":"test_username_2","password":"Pass1234@", "email": "test@email.com"})
    assert rv.status_code == 409

def test_register_duplicated_mail_and_username(client):
    rv = client.post("/register", 
            json={"username":"test_username","password":"Pass1234@", "email": "test@email.com"})
    assert rv.status_code == 409

def test_wrong_password(client):
    rv = client.post("/login", 
            json={"username":"test_username","password":"Pass1234"})
    assert rv.status_code == 403

def test_wrong_token(client):
    rv_2 = client.post("/puedoPasar?username=test_username", data=b"eybogustoken")
    assert rv_2.status_code == 401

def test_modify_mail(client):
    rv = client.post("/changeEmail", 
            json={"username":"test_username","password":"Pass1234@", "new_email":"test_username@email.com"})
    assert rv.status_code == 200

def test_modify_mail_to_existing_mail(client):
    client.post("/register", 
            json={"username":"test_username_2","password":"Pass1234@", "email": "test_2@email.com"})
        
    rv = client.post("/changeEmail", 
            json={"username":"test_username","password":"Pass1234@", "new_email":"test_2@email.com"})
    assert rv.status_code == 409

def test_modify_mail_with_wrong_pass(client):
    rv = client.post("/changeEmail", 
            json={"username":"test_username","password":"Pass1234", "new_email":"test_2@email.com"})
    assert rv.status_code == 403

def test_modify_pass_with_wrong_pass(client):
    rv = client.post("/changePassword", 
            json={"username":"test_username","password":"Pass1234", "new_password":"test_2@email.com"})
    assert rv.status_code == 403

def test_modify_pass_bad_request(client):
    rv = client.post("/changePassword", 
            json={"username":"test_username","old_password":"Pass1234", "new_password":"test_2@email.com"})
    assert rv.status_code == 400
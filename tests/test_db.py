import pytest
from db import *
from db.db_exceptions import *

@pytest.fixture
def db():
    db1 = DbInterface("test_db.json")
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    yield db1
    db1.remove_db()    


def test_add_user(db):
    user_creation = db.create_user("test_username_2","test@mail.com","testPAssword@123")
    assert user_creation

def test_retrieve_created_but_disabled_user(db):
    assert db.get_user("test_username", True).username == "test_username"

def test_retrieve_no_users(db):
    assert db.get_user("test_username_3") is None

def test_user_exists(db):
    assert db.user_exists("test_username")

def test_disable_user(db):
    _,token = db.create_user("test_username_2","test_2@mail.com","testPAssword@123")
    db.enable_user("test_username_2")
    db.disable_user("test_username_2")
    assert db.get_user("test_username_2", True).enabled is False

def test_disable_not_existent(db):
    with pytest.raises(ValueError):
        result = db.disable_user("test_username_3")

def test_verify_password(db):
    db.enable_user("test_username")
    assert db.verify_password("test_username","testPAssword@123")

def test_verify_password_user_not_exists(db):
    with pytest.raises(UserValidationException):
        db.verify_password("test_username_2","testPAssword@123")

def test_modify_password(db):
    db.enable_user("test_username")
    assert db.modify_password("test_username","testPAssword@123","testPAssword@124")
    assert db.verify_password("test_username","testPAssword@124")

def test_modify_password_raises(db):
    db.enable_user("test_username")
    with pytest.raises(UserValidationException):
        db.modify_password("test_usernam","testPAssword@123","testPAssword@124")
    with pytest.raises(UsernamePasswordMismatchException):
        db.modify_password("test_username","testPAssword@124","testPAssword@125")

def test_modify_password_out_of_compliance(db):
    db.enable_user("test_username")
    with pytest.raises(PasswordValidationException):
        db.modify_password("test_username","testPAssword@123","t")

def test_duplicated_user_returns_false(db):
    db.enable_user("test_username")
    result, _ = db.create_user("test_username","test_1@mail.com","testPAssword@123")
    assert result is False

def test_modify_to_duplicated(db):
    db.create_user("test_username_2","test_2@mail.com","testPAssword@123")
    db.enable_user("test_username_2")
    with pytest.raises(UserValidationException):
        db.modify_email("test_username_2","testPAssword@123","test_2@mail.com")
    with pytest.raises(UserValidationException):
        db.modify_email("test_username_2","testPAssword@123","test@mail.com")

def test_modify_mail(db):
    db.enable_user("test_username")
    assert db.modify_email("test_username","testPAssword@123","test@mail_2.com")
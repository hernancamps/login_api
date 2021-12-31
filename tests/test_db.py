import pytest
from db import *
from db.db_exceptions import *

def test_db_creation():
    db1 = DbInterface()
    assert isinstance(db1, DbInterface)

def test_add_user():
    db1 = DbInterface()
    user_creation = db1.create_user("test_username","test@mail.com","testPAssword@123")
    assert user_creation

def test_retrieve_created_but_disabled_user():
    db1 = DbInterface()
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    assert db1.get_user("test_username", True).username == "test_username"

def test_retrieve_no_users():
    db1 = DbInterface()
    assert db1.get_user("test_username") is None

def test_user_exists():
    db1 = DbInterface()
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    assert db1.user_exists("test_username")
    assert not db1.user_exists("test_username_2")

def test_disable_user():
    db1 = DbInterface()
    _,token = db1.create_user("test_username","test@mail.com","testPAssword@123")
    db1.enable_user("test_username")
    db1.disable_user("test_username")
    assert db1.get_user("test_username", True).enabled is False

def test_disable_not_existent():
    db1 = DbInterface()
    with pytest.raises(ValueError):
        result = db1.disable_user("test_username_2")

def test_verify_password():
    db1 = DbInterface()
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    db1.enable_user("test_username")
    assert db1.verify_password("test_username","testPAssword@123")

def test_verify_password_user_not_exists():
    db1 = DbInterface()
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    with pytest.raises(UserValidationException):
        db1.verify_password("test_username_2","testPAssword@123")

def test_modify_password():
    db1 = DbInterface()
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    db1.enable_user("test_username")
    assert db1.modify_password("test_username","testPAssword@123","testPAssword@124")
    assert db1.verify_password("test_username","testPAssword@124")

def test_modify_password_raises():
    db1 = DbInterface()
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    db1.enable_user("test_username")
    with pytest.raises(UserValidationException):
        db1.modify_password("test_usernam","testPAssword@123","testPAssword@124")
    with pytest.raises(UsernamePasswordMismatchException):
        db1.modify_password("test_username","testPAssword@124","testPAssword@125")

def test_modify_password_out_of_compliance():
    db1 = DbInterface()
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    db1.enable_user("test_username")
    with pytest.raises(PasswordValidationException):
        db1.modify_password("test_username","testPAssword@123","t")

def test_duplicated_user_raises():
    db1 = DbInterface()
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    db1.enable_user("test_username")
    assert db1.create_user("test_username","test_1@mail.com","testPAssword@123") is False
    assert db1.create_user("test_username_1","test@mail.com","testPAssword@123") is False

def test_modify_to_duplicated():
    db1 = DbInterface()
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    db1.create_user("test_username_2","test_2@mail.com","testPAssword@123")
    with pytest.raises(UserValidationException):
        db1.modify_email("test_username","testPAssword@123","test_2@mail.com")
    with pytest.raises(UserValidationException):
        db1.modify_email("test_username","testPAssword@123","test@mail.com")

def test_modify_mail():
    db1 = DbInterface()
    db1.create_user("test_username","test@mail.com","testPAssword@123")
    db1.enable_user("j4")
    assert db1.modify_email("test_username","testPAssword@123","test@mail_2.com")|
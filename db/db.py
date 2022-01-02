import os
from typing import Callable, List, Optional, Tuple
from pydantic import BaseModel, ValidationError, validator
from uuid import UUID, uuid4
from pydantic.networks import EmailStr
import bcrypt
from db.db_exceptions import *
from pydantic.types import UUID4, Json, StrictBool, StrictBytes, StrictStr
import re
import logging
import base64
from functools import wraps
import json 

reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
pattern = re.compile(reg)

logger = logging.getLogger("default")

class User(BaseModel):
    id: StrictStr
    username: StrictStr
    email: EmailStr
    password_hash: StrictStr
    enabled: StrictBool
    token_to_enable: StrictStr

    @validator("username")
    def valid_username(cls, v):
        if len(v) == 0:
            raise ValueError("user length can not be 0")
        if len(v.strip()) == 0:
            raise ValueError("user cant be only white space")
        if len(v) > 128:
            raise ValueError("username can not be bigger that 128 chars")
        return v

class JsonDb(BaseModel):
    users: List[Optional[User]]=[]

class DbInterface:

    def __init__(self, file_name="db.json"):
        self.__users = JsonDb()
        self.file_name = file_name
        self.save_to_file()

    def json(self):
        """
        This function takes the db and returns it as a string json
        taking advantage of pydantic .json methods
        """
        return self.__users.json()

    def save_to_file(self):
        """
        Saves the json to a file in disk
        """
        with open(self.file_name, "w") as file:
            file.write(self.__users.json())
    
    def read_from_file(self):
        """
        Reads a json and loads it from disk
        """
        with open(self.file_name, "r") as file:
            self.__users = JsonDb.parse_raw(file.read())

    def remove_db(self):
        """
        Cleans up
        """
        os.remove(self.file_name)

    @staticmethod
    def from_json(json_str:str) -> Callable:
        """
        Builds a Db from a json str
        Args:
            json_str
        Returns:
            DbInterface
        """
        db1 = DbInterface()
        db1.__users = JsonDb.parse_raw(json_str)
        return db1

    def user_exists(self, username) -> bool:
        """
        Takes the username and verifies wherever the user exists in the db
        Returns:
            bool True if the user exists False if it doesn't
        """
        self.read_from_file()
        return username in [u.username for u in self.__users.users]

    def user_exists_and_is_enabled(self, user_name: str) -> bool:
        """
        This function checks wherever the user exists in the db
        Args:
            user_name a str with the user_name
        Returns:
            bool true if it exists false otherwise
        """
        self.read_from_file()
        if len(self.__users.users) == 0:
            return False
        return user_name in [u.username for u in self.__users.users if u.enabled is True]
    
    def get_user(self, user_name: str, include_disabled: bool =False) -> Optional[User]:
        """
        If offered a username str it returns the User that matches exactly the
        username if it is enabled, None if it is not found
        Args:
            user_name a str
            include_disabled will get users even if disabled
        Returns:
            None if the user is not found
            User if the user is found
        Raises:
            ValueError This should never happen, if it does it means that there are two
            users with the same username in the db
        """
        self.read_from_file()
        if include_disabled:
            if not self.user_exists(user_name):
                return None
            search_list =[user for user in self.__users.users if user.username == user_name]
        else:
            if not self.user_exists_and_is_enabled(user_name):
                return None
            search_list =[user for user in self.__users.users if user.username == user_name and user.enabled]
        if len(search_list) == 1:
            return search_list[0]
        else:
            logger.error("Duplicated user: {username}".format(username=user_name))
            raise ValueError("Duplicated User") 

    def disable_user(self, user_name):
        """
        This sets the user from enabled to disabled
        user_name: a str representation of the user
        """
        self.read_from_file()
        if self.user_exists_and_is_enabled(user_name):
            self.get_user(user_name).enabled = False
        else:
            logger.error("user does not exist or is disabled: {username}".format(username=user_name))
            raise ValueError("user does not exist or is already disabled")
        self.save_to_file()

    def verify_password(self, username: str, password:str) -> bool:
        """
        This takes the username for the user and it's password,
        it uses bcrypt check pw functionality to check if the hash matches
        Args:
            username a str with the username
            password as tr with the password
        Returns:
            bool True if it is verified and False otherwise
        Raises:
            UserValidationException if the user does not exist or is not enabled
        """
        self.read_from_file()
        if not self.user_exists_and_is_enabled(username):
            raise UserValidationException("the requested user does not exist or is not enabled")
        user = self.get_user(username)
        return bcrypt.checkpw(password.encode(), user.password_hash.encode())    
    
    def mail_exists(self, email) -> bool:
        """
        Returns true if the mail exists, false otherwise
        Args:
            email a str
        Returns:
            bool
        """
        self.read_from_file
        if len(self.__users.users) == 0:
            return False
        return email in [u.email for u in self.__users.users]
    
    def create_user(self, user_name: str, email: str,password:str) -> Tuple[bool, str]:
        """
        It verifies that the user and the password are in compliance, if they are
        it creates the user with a hashed password and marked as enabled.
        Args:
            user_name a str with the proposed user name
            email an email with the requested email for the user
            password the proposed password
        Returns:
            a tuple with the success of the operation and the uuid of the token
        Raises:
            ValidationError if there is a problem with the actual user
            creation once it has been validated
        """
        self.read_from_file()
        try:
            self.verify_user_compliance(user_name, email)
            self.verify_password_compliance(password)
        except UserValidationException:
            logger.error("the user or the email already exist")
            return (False, None)
        except PasswordValidationException:
            logger.error("password does not comply with rules")
            raise
        try:
            password_hash = self.hash_password(password)
            token_to_enable=json.dumps({"username":user_name, "token":str(uuid4())})
            base64_encoded_token = base64.b64encode(token_to_enable.encode()).decode()
            user_to_add = User(
                id=str(uuid4()),
                username=user_name,
                email=email,enabled=False, 
                password_hash=password_hash,
                token_to_enable=base64_encoded_token)
            self.__users.users.append(user_to_add)
            self.save_to_file()
            return (True, user_to_add.token_to_enable)
        except ValidationError as e:
            logger.error("there was an error while hashing")
            raise
    
    def verify_user_compliance(self, user_name, email):
        """
        If checks if the user_name and the email are in compliance with the rules.
        In this instance it means that the user name does not exist and the email does not exist
        Args:
            user_name a str representing the user name
            email a str representing the email
        Returns:
            bool True if the user exists
        Raises:
            UserValidationException if the user or the Email exist
        """
        self.read_from_file()
        if self.user_exists(user_name):
            raise UserValidationException("The user already exists")
        if self.mail_exists(email):
            raise UserValidationException("This mail is already registered")
        self.save_to_file()
        return True

    def verify_password_compliance(self, password):
        """
        This verifies whetever the password is in compliance or not.
        For this it must have more than 8 chars, less than 128 chars
        and must include lower case upper case and special chars.
        Args:
            password the proposed password
        Returns:
            bool True if the password is compliant
        Raises:
            PasswordValidationException a comfy message with the rule that is not being 
            met 
        """
        self.read_from_file()
        if len(password) < 8:
            raise PasswordValidationException("password length must be higher than 8")
        if len(password) >= 128:
            raise PasswordValidationException("password length must be less than 128")
        mat = re.search(pattern, password)
        if not mat:
            raise PasswordValidationException("password must match rules")
        return True

    def hash_password(self, password) -> str:
        """
        It hashes the password with the bcrypt algorithm
        Args:
            password the password to be hashed
        Returns:
            str with the hashed password
        """
        password_to_hash = password.encode()
        password_hash = bcrypt.hashpw(password_to_hash, bcrypt.gensalt())
        return password_hash.decode()

    def modify_password(self, username, old_pass, new_pass) -> bool:
        """
        This functionality is to modify the password,it first verifies that the user exists and
        gets it, then it verifies that username and password are correct, 
        lastly it checks that the new password is in compliance with policy, if all this
        is correct then it changes the password.
        Args:
            username the user name
            old_pass the password to change
            new_pass the new password
        Returns:
            bool True if the operation was succesful
        Raises:
            UserValidationException if the user does not exist
            UsernamePasswordMismatchException if the username password combination is not correct
        """
        self.read_from_file()
        if not self.get_user(username):
            raise UserValidationException("user does not exist")
        if not self.verify_password(username,old_pass):
            raise UsernamePasswordMismatchException("the old password is not correct")
        self.verify_password_compliance(new_pass)
        self.get_user(username).password_hash = self.hash_password(new_pass)
        self.save_to_file()
        return True

    def modify_email(self, username, password, new_email) -> bool:
        """
        This function is used to modify the email registered for the user.
        It takes a username, a password and the new email.
        It checks that the username exists and is enabled, then it checks that 
        the username password combination is correct and if it is it checks 
        that the email does not exist in the db.
        If all this is correct it returns True after modifying the email.
        Args:
            username a str with the user
            password a str with the password
            new_email a str with the new email
        Returns:
            bool True if the user exists
        Raises:
            UserValidationException if the user does not exist or is inexistent
            UsernamePasswordMismatchException if the username password combination
            is incorrect
        """
        self.read_from_file()
        if not self.user_exists_and_is_enabled(username):
            raise UserValidationException("You are trying to modify an inexistent user")
        if not self.verify_password(username, password):
            raise UsernamePasswordMismatchException("Wrong password username combination")
        if self.mail_exists(new_email):
            raise UserValidationException("Mail already exists")
        self.get_user(username).email == new_email
        self.save_to_file()
        return True
    
    def validate_email(self, username: str, token: str):
        """
        It compares the token against the one stored in the db.
        It it matches it returns true, else it returns False

        """
        self.read_from_file()
        user = self.get_user(username, True)
        if str(user.token_to_enable) == token:
            return True
        return False

    def enable_user(self, username):
        """
        It enables the offered username
        """
        self.read_from_file()
        user = self.get_user(username, True)
        if user is None:
            raise UserValidationException("the required user does not exist")
        user.enabled = True
        self.save_to_file()
        
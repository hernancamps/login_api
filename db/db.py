from typing import List, Optional
from pydantic import BaseModel, ValidationError, validator
from uuid import UUID, uuid4
from pydantic.networks import EmailStr
import bcrypt
from pydantic.types import Json, StrictBool, StrictBytes, StrictStr
import re
import logging

reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
pattern = re.compile(reg)

logger = logging.getLogger("default")

class User(BaseModel):
    id: UUID
    username: StrictStr
    email: EmailStr
    password_hash: StrictBytes
    enabled: StrictBool

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

    def __init__(self):
        self.__users = JsonDb()

    def json(self):
        return self.__users.json()

    @staticmethod
    def from_json(json_str):
        db1 = DbInterface()
        db1.__users = JsonDb.parse_raw(json_str)
        return db1

    def user_exists(self, user_name: str) -> bool:
        """
        This function checks wherever the user exists in the db
        """
        if len(self.__users.users) == 0:
            return False
        return user_name in [u.username for u in self.__users.users]
    
    def get_user(self, user_name: str) -> Optional[User]:
        if self.__users.users == []:
            return None
        search_list =[user for user in self.__users.users if user.username == user_name]
        if len(search_list) == 1:
            return search_list[0]
        elif len(search_list) == 0:
            return None
        else:
            raise ValueError("This should never, never happen") 

    def disable_user(self, user_name):
        if self.user_exists(user_name):
            self.get_user(user_name).enabled = False
        
    def verify_password(self, username: str, password:str) -> bool:
        if not self.user_exists(username):
            raise ValueError("the requested user does not exist")
        user = self.get_user(username)
        return bcrypt.checkpw(password.encode(), user.password_hash)    
    
    def mail_exists(self, email):
        if len(self.__users.users) == 0:
            return False
        return email in [u.email for u in self.__users.users]
    

    def create_user(self, user_name: str, email: str,password:str) -> bool:
        self.verify_user_compliance(user_name, email)
        self.verify_password_compliance(password)
        try:
            password_hash = self.hash_password(password)
            user_to_add = User(id=uuid4(),username=user_name,email=email,enabled=True, password_hash=password_hash)
            self.__users.users.append(user_to_add)
            return True
        except ValidationError as e:
            logger.error("there was an error while hashing")
            raise

    def verify_user_compliance(self, user_name, email):
        if self.user_exists(user_name):
            raise ValueError("The user already exists")
        if self.mail_exists(email):
            raise ValueError("This mail is already registered")

    def verify_password_compliance(self, password):
        if len(password) < 8:
            raise ValueError("password length must be higher than 8")
        if len(password) >= 128:
            raise ValueError("password length must be less than 128")
        mat = re.search(pattern, password)
        if not mat:
            raise ValueError("password must match rules")
        return True

    def hash_password(self, password):
        password_to_hash = password.encode()
        password_hash = bcrypt.hashpw(password_to_hash, bcrypt.gensalt())
        return password_hash

    def modify_password(self, username, old_pass, new_pass):
        if not self.get_user(username):
            raise ValueError("user does not exist")
        if not self.verify_password(username,old_pass):
            raise ValueError("the old password is not correct")
        self.verify_password_compliance(new_pass)
        self.get_user(username).password_hash = self.hash_password(new_pass)
        return True

    def modify_email(self, username, password, new_email):
        if not self.user_exists(username):
            raise ValueError("You are trying to modify an inexistent user")
        if not self.verify_password(username, password):
            raise ValueError("Wrong password username combination")
        if self.mail_exists(new_email):
            raise ValueError("Mail already exists")
        self.get_user(username).email == new_email
        return True

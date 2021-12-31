from pydantic import BaseModel
from pydantic.networks import EmailStr
from pydantic.types import StrictStr

class ChangePasswordRequestValidation(BaseModel):
    username: StrictStr
    password: StrictStr
    new_password: StrictStr

class RegistrationRequestValidation(BaseModel):
    username: StrictStr
    password: StrictStr
    email: EmailStr

class LoginRequestValidation(BaseModel):
    username: StrictStr
    password: StrictStr

class EmailChangeRequestValidation(BaseModel):
    username: StrictStr
    password: StrictStr
    new_email: StrictStr

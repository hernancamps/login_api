from datetime import datetime, timedelta, timezone
from flask import Flask, request, make_response
from pydantic import ValidationError
from pydantic.main import BaseModel
from pydantic.networks import EmailStr
from pydantic.types import StrictStr
import jwt
from db import DbInterface
import os

JWT_SECRET = os.getenv("JWT_SECRET", "some random key, this should never be used in a prod setting")
app = Flask(__name__)
db = DbInterface()

class RegistrationRequestValidation(BaseModel):
    username: StrictStr
    password: StrictStr
    email: EmailStr

class LoginRequestValidation(BaseModel):
    username: StrictStr
    password: StrictStr

@app.route("/register",methods=["POST"])
def register_user():
    """
    This endpoint registers the user, it is expecting a
    json in the format:
    {
        "username":"username",
        "password":"some_password",
        "email":"some_email@mail.com"
    }
    It represents the creation path in the challenge.
    It will return: 
        409 in case that the user exists, or the mail
        exists or the password does not comply with the 
        policy
        400 if one of the required fields does not exist
        201 if the request was completed succesfully.

    """
    req = request.get_json()
    try:
        validated_request = RegistrationRequestValidation(**req)
    except ValidationError as v:
        return make_response(v.json(), 400)
    try:
        db.create_user(validated_request.username, validated_request.email, validated_request.password)
    except ValueError:
        return make_response("resource already exists", 409)
    return make_response("created", 201)

@app.route("/login", methods=["Post"])
def login_to_app():
    req = request.get_json()
    try:    
        validated_request = LoginRequestValidation(**req)
    except ValidationError as v:
        return make_response(v.json(), 400)
    try:
        db.verify_password(validated_request.username, validated_request.password)
    except ValueError as val_err:
        app.log.error("incorrect login attempt for user {username}".format(validated_request.username))
        return make_response("The username/password combination is incorrect", 403)
    encoded_jwt = jwt.encode({"username":validated_request.username, 
                            "exp":datetime.datetime.now(tz=timezone.utc)+timedelta(minutes=60)}, 
                            JWT_SECRET)
    return make_response(encoded_jwt, 200)

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

@app.route("/login", methods=["POST"])
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
                            "exp":datetime.now(tz=timezone.utc)+timedelta(minutes=60)}, 
                            JWT_SECRET)
    return make_response(encoded_jwt, 200)

@app.route("/puedoPasar", methods=["POST"])
def validate_token():
    username = request.args.get("user")
    token = request.get_data(as_text=True)
    try:
        decoded_jwt = jwt.decode(token, JWT_SECRET)
    except jwt.ExpiredSignatureError:
        return make_response("Please login again", 401)
    if username != token.get("username"):
        return make_response("there was a problem", 401)
    elif username == token.get("username"):
        return make_response("true", 200)
    else:
        app.logger("this shouldnt have happened: {username}".format(username=username))
        return make_response("this should not happen", 500)

@app.route("/changePassword", methods=["POST"])
def change_password():
    request_to_change = request.get_json()
    validated_request = ChangePasswordRequestValidation(**request_to_change)
    try:
        db.modify_password(validated_request.username, validated_request.password, validated_request.new_password)
    except ValueError:
        return make_response("wrong login/password combination", 409)
    # TODO: need to add logic for password not in compliance
    return make_response("ok", 200)

@app.route("/changeEmail", methods=["POST"])
def change_email():
    request_to_change = request.get_json()
    validated_request = EmailChangeRequestValidation(**request_to_change)
    try:
        db.modify_email(validated_request.username, validated_request.password, validated_request.new_email)
    except ValueError:
        make_response("there was a problem", 500)
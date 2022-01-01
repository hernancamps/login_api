from datetime import datetime, timedelta, timezone
from typing import Optional
from flask import Flask, request, make_response
from pydantic import ValidationError
import jwt
from db import DbInterface
from db.db_exceptions import *
from request_validations.validations import *

import os
import logging

from db.db_exceptions import UserValidationException, UsernamePasswordMismatchException

logger = logging.getLogger("default")


def create_app(db_name:Optional[str]=None, testing: bool=False) -> Flask:
    JWT_SECRET = os.getenv("JWT_SECRET", "some random key, this should never be used in a prod setting")
    app = Flask(__name__)
    if testing:
        app.config["testing"] = True

    if db_name is None:
        db = DbInterface()
    else:
        db = DbInterface(db_name)


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
        created, token = db.create_user(validated_request.username, validated_request.email, validated_request.password)
        if created:
            if testing:
                return make_response(str(token), 201)
            else:
                return make_response("created", 201)
        if not created:
            return make_response("resource already exists", 409)
    
    
    @app.route("/login", methods=["POST"])
    def login_to_app():
        """
        This endpoint takes a json with the format {"username": "user", "password":"pass}
        and returns a jwt token with an expiration date of one hour
        """
        req = request.get_json()
        try:    
            validated_request = LoginRequestValidation(**req)
        except ValidationError as v:
            return make_response(v.json(), 400)
        
        if not db.verify_password(validated_request.username, validated_request.password):
            logger.error("incorrect login attempt for user {username}".format(username=validated_request.username))
            return make_response("The username/password combination is incorrect", 403)
        elif db.verify_password(validated_request.username, validated_request.password):
            encoded_jwt = jwt.encode({"username":validated_request.username, 
                                "exp":datetime.now(tz=timezone.utc)+timedelta(minutes=60)}, 
                                JWT_SECRET)
            return make_response(encoded_jwt, 200)
        return make_response("error", 500)

    @app.route("/puedoPasar", methods=["POST"])
    def validate_token():
        """
        This endpoint takes care of decoding and validating the token,
        returns true if the token is valid and 401 otherwise
        """
        username = request.args.get("username")
        token = request.get_data(as_text=True)
        try:
            decoded_jwt = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return make_response("Please login again", 401)
        except jwt.exceptions.InvalidTokenError:
            return make_response("there was a problem", 401)
        if username != decoded_jwt.get("username"):
            return make_response("there was a problem", 401)
        elif username == decoded_jwt.get("username"):
            return make_response("true", 200)
        else:
            logger.error("this shouldnt have happened: {username}".format(username=username))
            return make_response("this should not happen", 500)

    @app.route("/changePassword", methods=["POST"])
    def change_password():
        """
        this endpoint allows for modifying the password, new
        password has to follow the pass policy
        """
        request_to_change = request.get_json()
        try:
            validated_request = ChangePasswordRequestValidation(**request_to_change)
        except ValidationError as v:
            return make_response(v.json(), 400)
        try:
            db.modify_password(validated_request.username, validated_request.password, validated_request.new_password)
        except (UsernamePasswordMismatchException):
            return make_response("wrong login/password combination", 403)
        except (UserValidationException):
            return make_response("inexistent user", 409)
        # TODO: need to add logic for password not in compliance
        return make_response("ok", 200)

    @app.route("/changeEmail", methods=["POST"])
    def change_email():
        """
        this is for changing the mail for the user, in this case it needs
        that the mail does not exist
        """
        request_to_change = request.get_json()
        try:
            validated_request = EmailChangeRequestValidation(**request_to_change)
        except ValidationError as v:
            return make_response(v.json(), 400)
        try:
            db.modify_email(validated_request.username, validated_request.password, validated_request.new_email)
            return make_response("ok", 200)
        except (UsernamePasswordMismatchException):
            return make_response("wrong login/password combination", 403)
        except (UserValidationException):
            return make_response("email already exists", 409)

    @app.route("/verifyEmail", methods=["GET"])
    def verify_email():
        username = request.args.get("username")
        token = request.args.get("token")
        if db.validate_email(username, token):
            db.enable_user(username)
            return make_response("ok", 200)
        else:
            return make_response("This token is not correct", 409)

    return app

if __name__ == "__main__":
    app = create_app()
    app.debug = True
    app.run()

Challenge 
---------------------------------------

How to set up my environment
---------------------------------------
Please be aware that this instructions may be vary depending on your
environment. This was done in a Ubuntu OS.

Before starting clone the repository and go to the root of the cloned repository.

Create an environment, I did this by running:

```bash
python3 -m venv venv
```

And then activate it by running:

```bash
source venv/bin/activate
```

Install dependencies
---------------------------------------
Make sure that the environment is activated and then run the following command
to install dependencies:

```bash
pip install -r requirements.txt
```

Run
---------------------------------------

You are all set, if you want to run the app use:

```bash
python api.py
```

Please be aware
---------------------------------------
The app will run in a flask development server with debugging activated.

How to
-----------------------------------------

Here I list the different endpoints, their functionalities and how to make the function-
You can register by placing a post request to the endpoint /register. This endpoint requires
a json with the fields:
    
    username
    password
    email

The endpoint requires that the username and email are unique, if other entries in the db
have the same email or username it should fail. It also enforces some basic validations on
    
    username and email: they must be unique, email must be a "valid" email address
    password: it must have special chars, upper caps, lower caps and numbers. It must
    have at least 8 chars.

This endpoint returns an activation token when it is in testing mode, by default in this 
repository. This token should be returned to the user through an email.

Activate
The created user is in disabled state untill it is activated. To activate please make
a get request in the endpoint: 127.0.0.1:5000/verifyEmail?token={token}

This will activate the user.

Login
To login you will need to make a post request to: 127.0.0.1:5000/login
The json should have the fields:

    username
    password

If succesfull t will return a JWT token that you can use against the puedoPasar endpoint.

puedoPasar
This endpoint is a post, it expexts the username as a parameter in the query and
the JWT token as the body of the request, it will return true if the token and the
username combination is correct.

changeEmail 
This endpoint allows you to change the registered email. It will check that the new
email is not already registered. The endpoint is 127.0.0.1:5000/changeEmail and it expects
a json with the following fields:

    username
    password
    new_email

changePassword
This endpoint will allow you to change the password. The endpoint address is 127.0.0.1:5000/changePassword it accepts a json and it must have the following fields.

    username
    password
    new_password

The new password must be compliant with the password policy.
---------------------------------------------------------
Example queries

Here you can find some example queries:

```bash

echo "Register"
curl -X POST 127.0.0.1:5000/register -H 'Content-Type: application/json' -d '{"username":"test_username","password":"testPass1234@", "email":"test@testmail.com"}' > token.txt
echo "Activate"
curl -X GET 127.0.0.1:5000/verifyEmail?token="$(cat token.txt)"
echo "Login"
curl -X POST 127.0.0.1:5000/login -H 'Content-Type: application/json' -d '{"username":"test_username","password":"testPass1234@"}' > token_login.txt
echo "puedo pasar"
curl -X POST 127.0.0.1:5000/puedoPasar?username=test_username -d "$(cat token_login.txt)"
echo "change password"
curl -X POST 127.0.0.1:5000/changePassword -H 'Content-Type: application/json' -d '{"username": "test_username", "password": "testPass1234@", "new_password":"testPass12345@"}'
echo "Login"
curl -X POST 127.0.0.1:5000/login -H 'Content-Type: application/json' -d '{"username":"test_username","password":"testPass12345@"}' > token_login.txt
echo "puedo pasar"
curl -X POST 127.0.0.1:5000/puedoPasar?username=test_username -H 'Content-Type: application/json' -d "$(cat token_login.txt)"
echo "Change Email"
curl -X POST 127.0.0.1:5000/changeEmail -H 'Content-Type: application/json' -d '{"username":"test_username","password":"testPass12345@", "new_email": "test_email_2_@test_email.com"}' 
```
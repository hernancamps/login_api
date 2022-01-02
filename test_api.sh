echo "Register"
curl -X POST 127.0.0.1:5000/register -H 'Content-Type: application/json' -d '{"username":"test_username","password":"testPass1234@", "email":"test@testmail.com"}' > token.txt
echo "Activate"
curl -X GET 127.0.0.1:5000/verifyEmail?token="$(cat token.txt)"
echo "Login"
curl -X POST 127.0.0.1:5000/login -H 'Content-Type: application/json' -d '{"username":"test_username","password":"testPass1234@"}' > token_login.txt
echo "puedo pasar"
curl -X POST 127.0.0.1:5000/puedoPasar?username=test_username -H 'Content-Type: application/json' -d "$(cat token_login.txt)"
echo "change password"
curl -X POST 127.0.0.1:5000/changePassword -H 'Content-Type: application/json' -d '{"username": "test_username", "password": "testPass1234@", "new_password":"testPass12345@"}'
echo "Login"
curl -X POST 127.0.0.1:5000/login -H 'Content-Type: application/json' -d '{"username":"test_username","password":"testPass12345@"}' > token_login.txt
echo "puedo pasar"
curl -X POST 127.0.0.1:5000/puedoPasar?username=test_username -H 'Content-Type: application/json' -d "$(cat token_login.txt)"
echo "Change Email"
curl -X POST 127.0.0.1:5000/changeEmail -H 'Content-Type: application/json' -d '{"username":"test_username","password":"testPass12345@", "new_email": "test_email_2_@test_email.com"}' 

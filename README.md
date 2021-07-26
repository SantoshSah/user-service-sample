# Please note that this repo is a sample used for demonstrating code structure. Though it builds successfully, it can not be used in production.

# Building server and client
 - to build server: go build ./cmd/user_server
 - to build client: go build ./cmd/user_server-cli


# Local Testing: REST
1) Register User
curl -d '{"email":"santoshsah4@gmail.com"}' -X POST https://app.local/api/v1/user/signup

2) Verify Confirmation Token
curl -d '{"userId":585985938150129665,"confirmationToken":371323}' -X POST http://app.local/api/v1/user/verifyConfirmationToken

3) Update Username
curl -d '{"name":"Santosh pd sah"}' -X POST https://app.local/api/v1/user/updateUsername -H "Authorization:your-auth-token"

4) Change Password
curl -d '{"password":"Qwerty"}' -X POST http://app.local/api/v1/user/changePassword -H "Authorization:your-auth-token"

5) Login
curl -d '{"email":"santoshsah4@gmail.com","password":"Qwerty"}' -X POST https://app.local/api/v1/user/login 

6) Refresh Access Token
curl -X POST https://app.local/api/v1/user/refreshAccessToken -H "Authorization:your-auth-token"

8) Reset Password
curl -d '{"email":"santoshsah4@gmail.com"}' -X POST http://app.local/api/v1/user/resetPassword

9) Verify Confirmation Token
curl -d '{"userId":475865469067493377,"passwordResetToken":865688}' -X POST http://app.local/api/v1/user/verifyPasswordResetToken

10) Logout:
curl -X POST https://app.local/api/v1/user/logout -H "Authorization:your-auth-token"

# Local Test: grpcurl
Ref: https://github.com/fullstorydev/grpcurl

1) Create new user

grpcurl -d '{"email":"santoshsah4@gmail.com"}' -proto user_service.proto app.local:443 user_service.UserService/Signup

2) Verify Confirmation Token

grpcurl -d '{"userId":596403424660324353,"confirmationToken":575537}' -proto user_service.proto app.local:443 user_service.UserService/VerifyConfirmationToken

3) Update User Name

grpcurl -H "Authorization:your-auth-token" -d '{"name":"Santosh pd sah"}' -proto user_service.proto app.local:443 user_service.UserService/UpdateUsername 

4) Change/Set Password

grpcurl -H "Authorization:your-auth-token" -d '{"password":"Qwerty"}' -proto user_service.proto app.local:443 user_service.UserService/ChangePassword 

5) Login

grpcurl -d '{"email":"santoshsah4@gmail.com","password":"Qwerty"}' -proto user_service.proto app.local:443 user_service.UserService/Login

6) Change user name after login: Repeat of step with Auth Token

grpcurl -H "Authorization:your-auth-token" -d '{"name":"Santosh prasad sah"}' -proto user_service.proto app.local:443 user_service.UserService/UpdateUsername

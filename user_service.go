package userapi

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"

	userservice "github.com/SantoshSah/user-service-sample/gen/user_service"
	"github.com/SantoshSah/user-service-sample/methods/auth"
	"github.com/SantoshSah/user-service-sample/types"
	jwt "github.com/dgrijalva/jwt-go"
	httptreemux "github.com/dimfeld/httptreemux/v5"
	redis "github.com/go-redis/redis/v8"
	"github.com/jinzhu/copier"
	"goa.design/goa"
	"goa.design/goa/v3/security"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

//Claims for JWT
var (
	claims = &types.JWTClaims{}
)

// user_service service example implementation.
// The example methods log the requests and return zero values.
type userServicesrvc struct {
	logger      *log.Logger
	gorm        *gorm.DB
	redisClient *redis.Client
}

// NewUserService returns the user_service service implementation.
func NewUserService(logger *log.Logger, gorm *gorm.DB, redisClient *redis.Client) userservice.Service {
	return &userServicesrvc{logger, gorm, redisClient}
}

// JWTAuth implements the authorization logic for service "user_service" for
// the "jwt" security scheme.
func (s *userServicesrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	//
	// TBD: add authorization logic.
	//
	// In case of authorization failure this function should return
	// one of the generated error structs, e.g.:
	//
	//    return ctx, myservice.MakeUnauthorizedError("invalid token")
	//
	// Alternatively this function may return an instance of
	// goa.ServiceError with a Name field value that matches one of
	// the design error names, e.g:
	//
	//    return ctx, goa.PermanentError("unauthorized", "invalid token")
	//

	foundInBlacklist, err := auth.IsBlacklisted(token)

	if err != nil {
		return ctx, goa.PermanentError("unauthorized", err.Error())
	}

	if foundInBlacklist == true {
		return ctx, goa.PermanentError("unauthorized", "Access Token black listed")
	}

	route := httptreemux.ContextRoute(ctx)

	if route != "/refreshAccessToken" {
		tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return auth.AccessTokenJwtKey, nil
		})

		if err != nil {
			return ctx, goa.PermanentError("unauthorized", err.Error())
		}

		if !tkn.Valid {
			return ctx, goa.PermanentError("unauthorized", "Invalid Token")
		}

	} else {
		tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return auth.RefreshTokenJwtKey, nil
		})

		if err != nil {
			return ctx, goa.PermanentError("unauthorized", err.Error())
		}

		if !tkn.Valid {
			return ctx, goa.PermanentError("unauthorized", "Invalid Token")
		}
	}

	return ctx, nil

}

// Signup implements signup.
func (s *userServicesrvc) Signup(ctx context.Context, p *userservice.SignupPayload) (userResult *userservice.Userresult, err error) {
	u := types.User{}
	userResult = &userservice.Userresult{}

	err = s.gorm.Unscoped().Where("email = ?", p.Email).First(&u).Error

	userResult.ID = &u.ID
	userResult.Email = &u.Email
	userResult.Name = &u.Name
	userResult.IsVerified = &u.IsVerified
	userResult.IsActive = &u.IsActive
	u.Email = p.Email

	//Create new user if user does not exist already
	if errors.Is(err, gorm.ErrRecordNotFound) {
		u.ConfirmationTokenExpiresAt = auth.GetConfirmationTokenExpirationTime()
		u.ConfirmationToken = auth.GenerateConfirmationToken()
		err = s.gorm.Create(&u).Error
	} else {
		if len(u.ID) > 0 && !u.IsActive {
			u.ConfirmationTokenExpiresAt = auth.GetConfirmationTokenExpirationTime()
			u.ConfirmationToken = auth.GenerateConfirmationToken()
			// Regenerate confirmation token if user has not already confirmed
			err = s.gorm.Unscoped().Model(&u).
				Updates(types.User{ConfirmationToken: u.ConfirmationToken, ConfirmationTokenExpiresAt: u.ConfirmationTokenExpiresAt}).Error
		}
	}

	if err == nil && len(u.ID) > 0 {
		/*
			toName := u.Email
			toEmail := u.Email

			if len(u.Name) > 0 {
				toName = u.Name
			}
		*/

		if !u.IsActive {
			if u.IsVerified {
				// Send OTP email
				// email.SendOTPEmail(toName, toEmail, u.ConfirmationToken)
			} else {
				//Send token confirmation email
				// email.SendConfirmationEmail(toName, toEmail, u.ConfirmationToken)
			}
		} else {
			// Send user registration status
			// email.SendAlreadyUserActiveEmail(toName, toEmail)
		}
	}

	return
}

// Verify Confirmation Token
func (s *userServicesrvc) VerifyConfirmationToken(ctx context.Context, p *userservice.VerifyConfirmationTokenPayload) (userResult *userservice.Userresult, err error) {
	u := types.User{}
	userResult = &userservice.Userresult{}

	err = s.gorm.Where("id = ?", p.UserID).First(&u).Error

	//Verify user
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = errors.New("User does not exist")
	} else if u.ConfirmationToken != p.ConfirmationToken {
		err = errors.New("Wrong confirmation token provided")
	} else if u.IsActive {
		err = errors.New("User already registered and active")
	} else if time.Now().Unix() > u.ConfirmationTokenExpiresAt.Unix() {
		err = errors.New("Confirmation token expired")
	} else {
		//Verify user by setting IsVerified=true
		err = s.gorm.Model(&u).Updates(types.User{IsVerified: true}).Error
		token, err := auth.GenerateAccessToken(u, true)

		if err == nil {
			userResult.ID = &u.ID
			userResult.Email = &u.Email
			userResult.Name = &u.Name
			userResult.IsVerified = &u.IsVerified
			userResult.IsActive = &u.IsActive
			userResult.AccessToken = &token
		}
	}

	return
}

// Verify Password reset token
func (s *userServicesrvc) VerifyPasswordResetToken(ctx context.Context, p *userservice.VerifyPasswordResetTokenPayload) (userResult *userservice.Userresult, err error) {
	u := types.User{}
	userResult = &userservice.Userresult{}

	err = s.gorm.Where("id = ?", p.UserID).First(&u).Error

	//Verify user
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = errors.New("User does not exist")
	} else if u.ConfirmationToken != p.PasswordResetToken {
		err = errors.New("Wrong password reset token provided")
	} else if time.Now().Unix() > u.ConfirmationTokenExpiresAt.Unix() {
		err = errors.New("Confirmation token expired")
	} else if !u.IsActive {
		err = errors.New("User is not active")
	} else {
		token, err := auth.GenerateAccessToken(u, true)

		if err == nil {
			userResult.ID = &u.ID
			userResult.Email = &u.Email
			userResult.Name = &u.Name
			userResult.IsVerified = &u.IsVerified
			userResult.IsActive = &u.IsActive
			userResult.AccessToken = &token
		}
	}
	return
}

func (s *userServicesrvc) UpdateUsername(ctx context.Context, p *userservice.UpdateUsernamePayload) (userResult *userservice.Userresult, err error) {
	u := types.User{}
	userResult = &userservice.Userresult{}

	err = s.gorm.Where("id = ?", claims.UserID).First(&u).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = errors.New("User does not exist")
	} else {
		err = s.gorm.Model(&u).Updates(types.User{Name: p.Name}).Error

		if err == nil {
			userResult.ID = &u.ID
			userResult.Email = &u.Email
			userResult.Name = &u.Name
			userResult.IsVerified = &u.IsVerified
			userResult.IsActive = &u.IsActive
		}
	}

	return
}

func (s *userServicesrvc) ChangePassword(ctx context.Context, p *userservice.ChangePasswordPayload) (userResult *userservice.Userresult, err error) {
	u := types.User{}
	userResult = &userservice.Userresult{}

	err = s.gorm.Where("id = ?", claims.UserID).First(&u).Error
	isUserActive := u.IsActive

	// Check if user exists
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = errors.New("User does not exist")
	} else {
		//Update password
		/*
					const (
			    MinCost     int = 4  // the minimum allowable cost as passed in to GenerateFromPassword
			    MaxCost     int = 31 // the maximum allowable cost as passed in to GenerateFromPassword
			    DefaultCost int = 10 // the cost that will actually be set if a cost below MinCost is passed into GenerateFromPassword
			)
		*/
		costOfHashing := 10
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(p.Password), costOfHashing)
		err = s.gorm.Model(&u).Updates(types.User{Password: string(hashedPassword), IsActive: true}).Error

		if err == nil {
			userResult.ID = &u.ID
			userResult.Email = &u.Email
			userResult.Name = &u.Name
			userResult.IsVerified = &u.IsVerified
			userResult.IsActive = &u.IsActive

			//Update User Roles and send Welcome email while setting up user account
			if !isUserActive {
				// Send Welcome Email
				// err = email.SendWelcomeEmail(u.Name, u.Email)
			}
		}
	}

	return
}

func (s *userServicesrvc) Login(ctx context.Context, p *userservice.LoginPayload) (userResult *userservice.Userresult, err error) {
	u := types.User{}
	userResult = &userservice.Userresult{}

	err = s.gorm.Where("email = ?", p.Email).First(&u).Error

	// Check if user exists
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = errors.New("User does not exist")
	} else if !u.IsActive {
		err = errors.New("User is not active")
	} else {
		// Compare the stored hashed password, with the hashed version of the password that was received
		if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(p.Password)); err != nil {
			// If the two passwords don't match, return error
			err = errors.New("Email and Password do not match")
		} else {
			var accessToken, refreshToken string = "", ""
			accessToken, refreshToken, err = auth.GenerateTokenPair(u)

			userResult.ID = &u.ID
			userResult.Email = &u.Email
			userResult.Name = &u.Name
			userResult.IsVerified = &u.IsVerified
			userResult.IsActive = &u.IsActive
			userResult.AccessToken = &accessToken
			userResult.RefreshToken = &refreshToken

			if err != nil {
				return nil, goa.PermanentError("ERROR", fmt.Sprintf("Could not login."))
			}
		}
	}

	return
}

func (s *userServicesrvc) Logout(ctx context.Context, p *userservice.LogoutPayload) (res *userservice.MessageResult, err error) {
	errorType := "ERROR"
	errorDesc := "Unknown error occured"

	//black list user after successful login
	err = auth.Blacklist(p.Token)
	errorType = "SUCCESS"
	errorDesc = "User logged out successfully"

	res = &userservice.MessageResult{}
	res.Type = &errorType
	res.Desc = &errorDesc
	return
}

func (s *userServicesrvc) RefreshAccessToken(ctx context.Context, p *userservice.RefreshAccessTokenPayload) (userResult *userservice.Userresult, err error) {
	u := types.User{}
	userResult = &userservice.Userresult{}

	/*
		// We ensure that a new token is not issued until enough time has elapsed
		// In this case, a new token will only be issued if the old token is within
		// 30 seconds of expiry. Otherwise, return a bad request status

		if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 5*time.Minute {
			err = errors.New("Enough time did not elapsed for new token")
			return
		}
	*/

	u.ID = claims.UserID
	u.Email = claims.UserEmail
	u.Name = claims.Username

	token, err := auth.GenerateAccessToken(u, false)
	// s.logger.Print("claims.UserID Refresh Access Token:", claims.UserID)
	userResult.AccessToken = &token

	return
}

func (s *userServicesrvc) ResetPassword(ctx context.Context, p *userservice.ResetPasswordPayload) (userResult *userservice.Userresult, err error) {
	u := types.User{}
	userResult = &userservice.Userresult{}

	err = s.gorm.Where("email = ?", p.Email).First(&u).Error

	//Create new user if user does not exist already
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = errors.New("User does not exist")
		return
	} else if !u.IsActive {
		err = errors.New("User is not active")
		return
	}

	u.ConfirmationToken = auth.GenerateConfirmationToken()
	u.ConfirmationTokenExpiresAt = auth.GetConfirmationTokenExpirationTime()

	// Regenerate confirmation token for resetting password
	err = s.gorm.Model(&u).
		Updates(types.User{ConfirmationToken: u.ConfirmationToken, ConfirmationTokenExpiresAt: u.ConfirmationTokenExpiresAt}).Error

	userResult.ID = &u.ID
	userResult.Email = &u.Email
	userResult.Name = &u.Name
	userResult.IsVerified = &u.IsVerified
	userResult.IsActive = &u.IsActive
	userResult.HasAgreed = &u.HasAgreed

	if err == nil {
		// Send Email
		// email.SendPasswordResetEmail(u.Name, u.Email, u.ConfirmationToken)
	}

	return
}

//Verify AuthToken
func (s *userServicesrvc) verifyAuthToken(token string) (bool, types.JWTClaims, error) {
	// Initialize a new instance of `Claims`
	claims := &types.JWTClaims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return auth.AccessTokenJwtKey, nil
	})

	if err != nil {
		return false, *claims, err
	}

	if !tkn.Valid {
		return false, *claims, errors.New("Token not valid")
	}

	return true, *claims, nil
}

// ListUsers implements ListUsers.
func (s *userServicesrvc) ListUsers(ctx context.Context, p *userservice.ListUsersPayload) (res *userservice.ListUsersResult, err error) {
	res = &userservice.ListUsersResult{}
	results := make([]types.User, 0)

	// Pagination Info
	pageNumber := int(1)
	pageSize := int(15)
	totalCount := int64(0)

	pageInfo := &userservice.Pageinfo{}

	pageInfo.PageNumber = &pageNumber
	pageInfo.PageSize = &pageSize

	if !reflect.ValueOf(p.PageNumber).IsNil() {
		pageNumber = *p.PageNumber
	}

	if !reflect.ValueOf(p.PageSize).IsNil() {
		pageSize = *p.PageSize
	}

	query := s.gorm.Table("users u")

	if !reflect.ValueOf(p.Email).IsNil() {
		query = query.Where("LOWER(u.email) LIKE ?", "%"+strings.ToLower(*p.Email)+"%")
	}

	if !reflect.ValueOf(p.MobileNumber).IsNil() {
		query = query.Where("LOWER(u.mobile_number) LIKE ?", "%"+strings.ToLower(*p.MobileNumber)+"%")
	}

	if !reflect.ValueOf(p.Name).IsNil() {
		query = query.Where("LOWER(u.name) LIKE ?", "%"+strings.ToLower(*p.Name)+"%")
	}

	if !reflect.ValueOf(p.Role).IsNil() {
		query = query.Where("LOWER(r.name) LIKE ?", "%"+strings.ToLower(*p.Role)+"%")
	}

	if !reflect.ValueOf(p.IsActive).IsNil() {
		query = query.Where("u.is_active = ?", *p.IsActive)
	}

	if !reflect.ValueOf(p.IsVerified).IsNil() {
		query = query.Where("u.is_verified = ?", *p.IsVerified)
	}

	if !reflect.ValueOf(p.HasAgreed).IsNil() {
		query = query.Where("u.has_agreed = ?", *p.HasAgreed)
	}

	var selectQuery strings.Builder
	selectQuery.WriteString("u.id")
	selectQuery.WriteString(",u.name")
	selectQuery.WriteString(",u.email")
	selectQuery.WriteString(",u.is_verified")
	selectQuery.WriteString(",u.is_active")
	selectQuery.WriteString(",u.has_agreed")

	query = query.
		Select(selectQuery.String()).
		Joins("INNER JOIN user_roles ur ON ur.user_id = u.id").
		Joins("INNER JOIN roles r ON r.id = ur.role_id")

	totalCountErr := query.Count(&totalCount).Error
	if totalCountErr != nil {
		return nil, goa.PermanentError("invalid", "Error counting records")
	}

	offset := (pageNumber - 1) * pageSize
	err = query.Offset(offset).
		Limit(pageSize).
		Preload("Roles").
		Preload("Roles.Role").
		Find(&results).Error

	if err != nil {
		return nil, goa.PermanentError("invalid", "could not fetch user records")
	}

	resultCount := int(len(results))
	pageInfo.Count = &resultCount
	pageInfo.TotalCount = &totalCount
	res.PageInfo = pageInfo

	copier.Copy(&res.Results, &results)

	return
}

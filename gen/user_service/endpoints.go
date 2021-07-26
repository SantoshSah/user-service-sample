// Code generated by goa v3.2.4, DO NOT EDIT.
//
// user_service endpoints
//
// Command:
// $ goa gen github.com/SantoshSah/user-service-sample/design

package userservice

import (
	"context"

	goa "goa.design/goa/v3/pkg"
	"goa.design/goa/v3/security"
)

// Endpoints wraps the "user_service" service endpoints.
type Endpoints struct {
	Signup                   goa.Endpoint
	VerifyConfirmationToken  goa.Endpoint
	UpdateUsername           goa.Endpoint
	VerifyPasswordResetToken goa.Endpoint
	ResetPassword            goa.Endpoint
	ChangePassword           goa.Endpoint
	Login                    goa.Endpoint
	RefreshAccessToken       goa.Endpoint
	Logout                   goa.Endpoint
	ListUsers                goa.Endpoint
}

// NewEndpoints wraps the methods of the "user_service" service with endpoints.
func NewEndpoints(s Service) *Endpoints {
	// Casting service to Auther interface
	a := s.(Auther)
	return &Endpoints{
		Signup:                   NewSignupEndpoint(s),
		VerifyConfirmationToken:  NewVerifyConfirmationTokenEndpoint(s),
		UpdateUsername:           NewUpdateUsernameEndpoint(s, a.JWTAuth),
		VerifyPasswordResetToken: NewVerifyPasswordResetTokenEndpoint(s),
		ResetPassword:            NewResetPasswordEndpoint(s),
		ChangePassword:           NewChangePasswordEndpoint(s, a.JWTAuth),
		Login:                    NewLoginEndpoint(s),
		RefreshAccessToken:       NewRefreshAccessTokenEndpoint(s, a.JWTAuth),
		Logout:                   NewLogoutEndpoint(s, a.JWTAuth),
		ListUsers:                NewListUsersEndpoint(s, a.JWTAuth),
	}
}

// Use applies the given middleware to all the "user_service" service endpoints.
func (e *Endpoints) Use(m func(goa.Endpoint) goa.Endpoint) {
	e.Signup = m(e.Signup)
	e.VerifyConfirmationToken = m(e.VerifyConfirmationToken)
	e.UpdateUsername = m(e.UpdateUsername)
	e.VerifyPasswordResetToken = m(e.VerifyPasswordResetToken)
	e.ResetPassword = m(e.ResetPassword)
	e.ChangePassword = m(e.ChangePassword)
	e.Login = m(e.Login)
	e.RefreshAccessToken = m(e.RefreshAccessToken)
	e.Logout = m(e.Logout)
	e.ListUsers = m(e.ListUsers)
}

// NewSignupEndpoint returns an endpoint function that calls the method
// "signup" of service "user_service".
func NewSignupEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*SignupPayload)
		res, err := s.Signup(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserresult(res, "default")
		return vres, nil
	}
}

// NewVerifyConfirmationTokenEndpoint returns an endpoint function that calls
// the method "verifyConfirmationToken" of service "user_service".
func NewVerifyConfirmationTokenEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*VerifyConfirmationTokenPayload)
		res, err := s.VerifyConfirmationToken(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserresult(res, "default")
		return vres, nil
	}
}

// NewUpdateUsernameEndpoint returns an endpoint function that calls the method
// "updateUsername" of service "user_service".
func NewUpdateUsernameEndpoint(s Service, authJWTFn security.AuthJWTFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*UpdateUsernamePayload)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{"system:write", "system:read"},
			RequiredScopes: []string{},
		}
		ctx, err = authJWTFn(ctx, p.Token, &sc)
		if err != nil {
			return nil, err
		}
		res, err := s.UpdateUsername(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserresult(res, "default")
		return vres, nil
	}
}

// NewVerifyPasswordResetTokenEndpoint returns an endpoint function that calls
// the method "verifyPasswordResetToken" of service "user_service".
func NewVerifyPasswordResetTokenEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*VerifyPasswordResetTokenPayload)
		res, err := s.VerifyPasswordResetToken(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserresult(res, "default")
		return vres, nil
	}
}

// NewResetPasswordEndpoint returns an endpoint function that calls the method
// "resetPassword" of service "user_service".
func NewResetPasswordEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*ResetPasswordPayload)
		res, err := s.ResetPassword(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserresult(res, "default")
		return vres, nil
	}
}

// NewChangePasswordEndpoint returns an endpoint function that calls the method
// "changePassword" of service "user_service".
func NewChangePasswordEndpoint(s Service, authJWTFn security.AuthJWTFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*ChangePasswordPayload)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{"system:write", "system:read"},
			RequiredScopes: []string{},
		}
		ctx, err = authJWTFn(ctx, p.Token, &sc)
		if err != nil {
			return nil, err
		}
		res, err := s.ChangePassword(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserresult(res, "default")
		return vres, nil
	}
}

// NewLoginEndpoint returns an endpoint function that calls the method "login"
// of service "user_service".
func NewLoginEndpoint(s Service) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*LoginPayload)
		res, err := s.Login(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserresult(res, "default")
		return vres, nil
	}
}

// NewRefreshAccessTokenEndpoint returns an endpoint function that calls the
// method "refreshAccessToken" of service "user_service".
func NewRefreshAccessTokenEndpoint(s Service, authJWTFn security.AuthJWTFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*RefreshAccessTokenPayload)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{"system:write", "system:read"},
			RequiredScopes: []string{},
		}
		ctx, err = authJWTFn(ctx, p.Token, &sc)
		if err != nil {
			return nil, err
		}
		res, err := s.RefreshAccessToken(ctx, p)
		if err != nil {
			return nil, err
		}
		vres := NewViewedUserresult(res, "default")
		return vres, nil
	}
}

// NewLogoutEndpoint returns an endpoint function that calls the method
// "logout" of service "user_service".
func NewLogoutEndpoint(s Service, authJWTFn security.AuthJWTFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*LogoutPayload)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{"system:write", "system:read"},
			RequiredScopes: []string{},
		}
		ctx, err = authJWTFn(ctx, p.Token, &sc)
		if err != nil {
			return nil, err
		}
		return s.Logout(ctx, p)
	}
}

// NewListUsersEndpoint returns an endpoint function that calls the method
// "listUsers" of service "user_service".
func NewListUsersEndpoint(s Service, authJWTFn security.AuthJWTFunc) goa.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		p := req.(*ListUsersPayload)
		var err error
		sc := security.JWTScheme{
			Name:           "jwt",
			Scopes:         []string{"system:write", "system:read"},
			RequiredScopes: []string{},
		}
		ctx, err = authJWTFn(ctx, p.Token, &sc)
		if err != nil {
			return nil, err
		}
		return s.ListUsers(ctx, p)
	}
}
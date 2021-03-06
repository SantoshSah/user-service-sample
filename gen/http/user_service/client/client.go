// Code generated by goa v3.2.4, DO NOT EDIT.
//
// user_service client HTTP transport
//
// Command:
// $ goa gen github.com/SantoshSah/user-service-sample/design

package client

import (
	"context"
	"net/http"

	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// Client lists the user_service service endpoint HTTP clients.
type Client struct {
	// Signup Doer is the HTTP client used to make requests to the signup endpoint.
	SignupDoer goahttp.Doer

	// VerifyConfirmationToken Doer is the HTTP client used to make requests to the
	// verifyConfirmationToken endpoint.
	VerifyConfirmationTokenDoer goahttp.Doer

	// UpdateUsername Doer is the HTTP client used to make requests to the
	// updateUsername endpoint.
	UpdateUsernameDoer goahttp.Doer

	// VerifyPasswordResetToken Doer is the HTTP client used to make requests to
	// the verifyPasswordResetToken endpoint.
	VerifyPasswordResetTokenDoer goahttp.Doer

	// ResetPassword Doer is the HTTP client used to make requests to the
	// resetPassword endpoint.
	ResetPasswordDoer goahttp.Doer

	// ChangePassword Doer is the HTTP client used to make requests to the
	// changePassword endpoint.
	ChangePasswordDoer goahttp.Doer

	// Login Doer is the HTTP client used to make requests to the login endpoint.
	LoginDoer goahttp.Doer

	// RefreshAccessToken Doer is the HTTP client used to make requests to the
	// refreshAccessToken endpoint.
	RefreshAccessTokenDoer goahttp.Doer

	// Logout Doer is the HTTP client used to make requests to the logout endpoint.
	LogoutDoer goahttp.Doer

	// ListUsers Doer is the HTTP client used to make requests to the listUsers
	// endpoint.
	ListUsersDoer goahttp.Doer

	// CORS Doer is the HTTP client used to make requests to the  endpoint.
	CORSDoer goahttp.Doer

	// RestoreResponseBody controls whether the response bodies are reset after
	// decoding so they can be read again.
	RestoreResponseBody bool

	scheme  string
	host    string
	encoder func(*http.Request) goahttp.Encoder
	decoder func(*http.Response) goahttp.Decoder
}

// NewClient instantiates HTTP clients for all the user_service service servers.
func NewClient(
	scheme string,
	host string,
	doer goahttp.Doer,
	enc func(*http.Request) goahttp.Encoder,
	dec func(*http.Response) goahttp.Decoder,
	restoreBody bool,
) *Client {
	return &Client{
		SignupDoer:                   doer,
		VerifyConfirmationTokenDoer:  doer,
		UpdateUsernameDoer:           doer,
		VerifyPasswordResetTokenDoer: doer,
		ResetPasswordDoer:            doer,
		ChangePasswordDoer:           doer,
		LoginDoer:                    doer,
		RefreshAccessTokenDoer:       doer,
		LogoutDoer:                   doer,
		ListUsersDoer:                doer,
		CORSDoer:                     doer,
		RestoreResponseBody:          restoreBody,
		scheme:                       scheme,
		host:                         host,
		decoder:                      dec,
		encoder:                      enc,
	}
}

// Signup returns an endpoint that makes HTTP requests to the user_service
// service signup server.
func (c *Client) Signup() goa.Endpoint {
	var (
		encodeRequest  = EncodeSignupRequest(c.encoder)
		decodeResponse = DecodeSignupResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v interface{}) (interface{}, error) {
		req, err := c.BuildSignupRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.SignupDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("user_service", "signup", err)
		}
		return decodeResponse(resp)
	}
}

// VerifyConfirmationToken returns an endpoint that makes HTTP requests to the
// user_service service verifyConfirmationToken server.
func (c *Client) VerifyConfirmationToken() goa.Endpoint {
	var (
		encodeRequest  = EncodeVerifyConfirmationTokenRequest(c.encoder)
		decodeResponse = DecodeVerifyConfirmationTokenResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v interface{}) (interface{}, error) {
		req, err := c.BuildVerifyConfirmationTokenRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.VerifyConfirmationTokenDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("user_service", "verifyConfirmationToken", err)
		}
		return decodeResponse(resp)
	}
}

// UpdateUsername returns an endpoint that makes HTTP requests to the
// user_service service updateUsername server.
func (c *Client) UpdateUsername() goa.Endpoint {
	var (
		encodeRequest  = EncodeUpdateUsernameRequest(c.encoder)
		decodeResponse = DecodeUpdateUsernameResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v interface{}) (interface{}, error) {
		req, err := c.BuildUpdateUsernameRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.UpdateUsernameDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("user_service", "updateUsername", err)
		}
		return decodeResponse(resp)
	}
}

// VerifyPasswordResetToken returns an endpoint that makes HTTP requests to the
// user_service service verifyPasswordResetToken server.
func (c *Client) VerifyPasswordResetToken() goa.Endpoint {
	var (
		encodeRequest  = EncodeVerifyPasswordResetTokenRequest(c.encoder)
		decodeResponse = DecodeVerifyPasswordResetTokenResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v interface{}) (interface{}, error) {
		req, err := c.BuildVerifyPasswordResetTokenRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.VerifyPasswordResetTokenDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("user_service", "verifyPasswordResetToken", err)
		}
		return decodeResponse(resp)
	}
}

// ResetPassword returns an endpoint that makes HTTP requests to the
// user_service service resetPassword server.
func (c *Client) ResetPassword() goa.Endpoint {
	var (
		encodeRequest  = EncodeResetPasswordRequest(c.encoder)
		decodeResponse = DecodeResetPasswordResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v interface{}) (interface{}, error) {
		req, err := c.BuildResetPasswordRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.ResetPasswordDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("user_service", "resetPassword", err)
		}
		return decodeResponse(resp)
	}
}

// ChangePassword returns an endpoint that makes HTTP requests to the
// user_service service changePassword server.
func (c *Client) ChangePassword() goa.Endpoint {
	var (
		encodeRequest  = EncodeChangePasswordRequest(c.encoder)
		decodeResponse = DecodeChangePasswordResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v interface{}) (interface{}, error) {
		req, err := c.BuildChangePasswordRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.ChangePasswordDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("user_service", "changePassword", err)
		}
		return decodeResponse(resp)
	}
}

// Login returns an endpoint that makes HTTP requests to the user_service
// service login server.
func (c *Client) Login() goa.Endpoint {
	var (
		encodeRequest  = EncodeLoginRequest(c.encoder)
		decodeResponse = DecodeLoginResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v interface{}) (interface{}, error) {
		req, err := c.BuildLoginRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.LoginDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("user_service", "login", err)
		}
		return decodeResponse(resp)
	}
}

// RefreshAccessToken returns an endpoint that makes HTTP requests to the
// user_service service refreshAccessToken server.
func (c *Client) RefreshAccessToken() goa.Endpoint {
	var (
		encodeRequest  = EncodeRefreshAccessTokenRequest(c.encoder)
		decodeResponse = DecodeRefreshAccessTokenResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v interface{}) (interface{}, error) {
		req, err := c.BuildRefreshAccessTokenRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.RefreshAccessTokenDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("user_service", "refreshAccessToken", err)
		}
		return decodeResponse(resp)
	}
}

// Logout returns an endpoint that makes HTTP requests to the user_service
// service logout server.
func (c *Client) Logout() goa.Endpoint {
	var (
		encodeRequest  = EncodeLogoutRequest(c.encoder)
		decodeResponse = DecodeLogoutResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v interface{}) (interface{}, error) {
		req, err := c.BuildLogoutRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.LogoutDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("user_service", "logout", err)
		}
		return decodeResponse(resp)
	}
}

// ListUsers returns an endpoint that makes HTTP requests to the user_service
// service listUsers server.
func (c *Client) ListUsers() goa.Endpoint {
	var (
		encodeRequest  = EncodeListUsersRequest(c.encoder)
		decodeResponse = DecodeListUsersResponse(c.decoder, c.RestoreResponseBody)
	)
	return func(ctx context.Context, v interface{}) (interface{}, error) {
		req, err := c.BuildListUsersRequest(ctx, v)
		if err != nil {
			return nil, err
		}
		err = encodeRequest(req, v)
		if err != nil {
			return nil, err
		}
		resp, err := c.ListUsersDoer.Do(req)
		if err != nil {
			return nil, goahttp.ErrRequestError("user_service", "listUsers", err)
		}
		return decodeResponse(resp)
	}
}

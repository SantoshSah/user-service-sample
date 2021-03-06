// Code generated by goa v3.2.4, DO NOT EDIT.
//
// user_service HTTP server encoders and decoders
//
// Command:
// $ goa gen github.com/SantoshSah/user-service-sample/design

package server

import (
	"context"
	"io"
	"net/http"
	"strings"

	userservice "github.com/SantoshSah/user-service-sample/gen/user_service"
	userserviceviews "github.com/SantoshSah/user-service-sample/gen/user_service/views"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

// EncodeSignupResponse returns an encoder for responses returned by the
// user_service signup endpoint.
func EncodeSignupResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*userserviceviews.Userresult)
		enc := encoder(ctx, w)
		body := NewSignupResponseBody(res.Projected)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeSignupRequest returns a decoder for requests sent to the user_service
// signup endpoint.
func DecodeSignupRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			body SignupRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}
		err = ValidateSignupRequestBody(&body)
		if err != nil {
			return nil, err
		}

		var (
			tenant string
		)
		tenant = r.Header.Get("tenant")
		if tenant == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("tenant", "header"))
		}
		if err != nil {
			return nil, err
		}
		payload := NewSignupPayload(&body, tenant)

		return payload, nil
	}
}

// EncodeSignupError returns an encoder for errors returned by the signup
// user_service endpoint.
func EncodeSignupError(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder, formatter func(err error) goahttp.Statuser) func(context.Context, http.ResponseWriter, error) error {
	encodeError := goahttp.ErrorEncoder(encoder, formatter)
	return func(ctx context.Context, w http.ResponseWriter, v error) error {
		en, ok := v.(ErrorNamer)
		if !ok {
			return encodeError(ctx, w, v)
		}
		switch en.ErrorName() {
		case "NotFound":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewSignupNotFoundResponseBody(res)
			}
			w.Header().Set("goa-error", "NotFound")
			w.WriteHeader(http.StatusNotFound)
			return enc.Encode(body)
		case "BadRequest":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewSignupBadRequestResponseBody(res)
			}
			w.Header().Set("goa-error", "BadRequest")
			w.WriteHeader(http.StatusBadRequest)
			return enc.Encode(body)
		default:
			return encodeError(ctx, w, v)
		}
	}
}

// EncodeVerifyConfirmationTokenResponse returns an encoder for responses
// returned by the user_service verifyConfirmationToken endpoint.
func EncodeVerifyConfirmationTokenResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*userserviceviews.Userresult)
		enc := encoder(ctx, w)
		body := NewVerifyConfirmationTokenResponseBody(res.Projected)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeVerifyConfirmationTokenRequest returns a decoder for requests sent to
// the user_service verifyConfirmationToken endpoint.
func DecodeVerifyConfirmationTokenRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			body VerifyConfirmationTokenRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}
		err = ValidateVerifyConfirmationTokenRequestBody(&body)
		if err != nil {
			return nil, err
		}

		var (
			tenant string
		)
		tenant = r.Header.Get("tenant")
		if tenant == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("tenant", "header"))
		}
		if err != nil {
			return nil, err
		}
		payload := NewVerifyConfirmationTokenPayload(&body, tenant)

		return payload, nil
	}
}

// EncodeVerifyConfirmationTokenError returns an encoder for errors returned by
// the verifyConfirmationToken user_service endpoint.
func EncodeVerifyConfirmationTokenError(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder, formatter func(err error) goahttp.Statuser) func(context.Context, http.ResponseWriter, error) error {
	encodeError := goahttp.ErrorEncoder(encoder, formatter)
	return func(ctx context.Context, w http.ResponseWriter, v error) error {
		en, ok := v.(ErrorNamer)
		if !ok {
			return encodeError(ctx, w, v)
		}
		switch en.ErrorName() {
		case "NotFound":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewVerifyConfirmationTokenNotFoundResponseBody(res)
			}
			w.Header().Set("goa-error", "NotFound")
			w.WriteHeader(http.StatusNotFound)
			return enc.Encode(body)
		case "BadRequest":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewVerifyConfirmationTokenBadRequestResponseBody(res)
			}
			w.Header().Set("goa-error", "BadRequest")
			w.WriteHeader(http.StatusBadRequest)
			return enc.Encode(body)
		default:
			return encodeError(ctx, w, v)
		}
	}
}

// EncodeUpdateUsernameResponse returns an encoder for responses returned by
// the user_service updateUsername endpoint.
func EncodeUpdateUsernameResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*userserviceviews.Userresult)
		enc := encoder(ctx, w)
		body := NewUpdateUsernameResponseBody(res.Projected)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeUpdateUsernameRequest returns a decoder for requests sent to the
// user_service updateUsername endpoint.
func DecodeUpdateUsernameRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			body UpdateUsernameRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}
		err = ValidateUpdateUsernameRequestBody(&body)
		if err != nil {
			return nil, err
		}

		var (
			tenant string
			token  string
		)
		tenant = r.Header.Get("tenant")
		if tenant == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("tenant", "header"))
		}
		token = r.Header.Get("Authorization")
		if token == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("Authorization", "header"))
		}
		if err != nil {
			return nil, err
		}
		payload := NewUpdateUsernamePayload(&body, tenant, token)
		if strings.Contains(payload.Token, " ") {
			// Remove authorization scheme prefix (e.g. "Bearer")
			cred := strings.SplitN(payload.Token, " ", 2)[1]
			payload.Token = cred
		}

		return payload, nil
	}
}

// EncodeUpdateUsernameError returns an encoder for errors returned by the
// updateUsername user_service endpoint.
func EncodeUpdateUsernameError(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder, formatter func(err error) goahttp.Statuser) func(context.Context, http.ResponseWriter, error) error {
	encodeError := goahttp.ErrorEncoder(encoder, formatter)
	return func(ctx context.Context, w http.ResponseWriter, v error) error {
		en, ok := v.(ErrorNamer)
		if !ok {
			return encodeError(ctx, w, v)
		}
		switch en.ErrorName() {
		case "NotFound":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewUpdateUsernameNotFoundResponseBody(res)
			}
			w.Header().Set("goa-error", "NotFound")
			w.WriteHeader(http.StatusNotFound)
			return enc.Encode(body)
		case "BadRequest":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewUpdateUsernameBadRequestResponseBody(res)
			}
			w.Header().Set("goa-error", "BadRequest")
			w.WriteHeader(http.StatusBadRequest)
			return enc.Encode(body)
		default:
			return encodeError(ctx, w, v)
		}
	}
}

// EncodeVerifyPasswordResetTokenResponse returns an encoder for responses
// returned by the user_service verifyPasswordResetToken endpoint.
func EncodeVerifyPasswordResetTokenResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*userserviceviews.Userresult)
		enc := encoder(ctx, w)
		body := NewVerifyPasswordResetTokenResponseBody(res.Projected)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeVerifyPasswordResetTokenRequest returns a decoder for requests sent to
// the user_service verifyPasswordResetToken endpoint.
func DecodeVerifyPasswordResetTokenRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			body VerifyPasswordResetTokenRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}
		err = ValidateVerifyPasswordResetTokenRequestBody(&body)
		if err != nil {
			return nil, err
		}

		var (
			tenant string
		)
		tenant = r.Header.Get("tenant")
		if tenant == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("tenant", "header"))
		}
		if err != nil {
			return nil, err
		}
		payload := NewVerifyPasswordResetTokenPayload(&body, tenant)

		return payload, nil
	}
}

// EncodeVerifyPasswordResetTokenError returns an encoder for errors returned
// by the verifyPasswordResetToken user_service endpoint.
func EncodeVerifyPasswordResetTokenError(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder, formatter func(err error) goahttp.Statuser) func(context.Context, http.ResponseWriter, error) error {
	encodeError := goahttp.ErrorEncoder(encoder, formatter)
	return func(ctx context.Context, w http.ResponseWriter, v error) error {
		en, ok := v.(ErrorNamer)
		if !ok {
			return encodeError(ctx, w, v)
		}
		switch en.ErrorName() {
		case "NotFound":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewVerifyPasswordResetTokenNotFoundResponseBody(res)
			}
			w.Header().Set("goa-error", "NotFound")
			w.WriteHeader(http.StatusNotFound)
			return enc.Encode(body)
		case "BadRequest":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewVerifyPasswordResetTokenBadRequestResponseBody(res)
			}
			w.Header().Set("goa-error", "BadRequest")
			w.WriteHeader(http.StatusBadRequest)
			return enc.Encode(body)
		default:
			return encodeError(ctx, w, v)
		}
	}
}

// EncodeResetPasswordResponse returns an encoder for responses returned by the
// user_service resetPassword endpoint.
func EncodeResetPasswordResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*userserviceviews.Userresult)
		enc := encoder(ctx, w)
		body := NewResetPasswordResponseBody(res.Projected)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeResetPasswordRequest returns a decoder for requests sent to the
// user_service resetPassword endpoint.
func DecodeResetPasswordRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			body ResetPasswordRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}
		err = ValidateResetPasswordRequestBody(&body)
		if err != nil {
			return nil, err
		}

		var (
			tenant string
		)
		tenant = r.Header.Get("tenant")
		if tenant == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("tenant", "header"))
		}
		if err != nil {
			return nil, err
		}
		payload := NewResetPasswordPayload(&body, tenant)

		return payload, nil
	}
}

// EncodeResetPasswordError returns an encoder for errors returned by the
// resetPassword user_service endpoint.
func EncodeResetPasswordError(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder, formatter func(err error) goahttp.Statuser) func(context.Context, http.ResponseWriter, error) error {
	encodeError := goahttp.ErrorEncoder(encoder, formatter)
	return func(ctx context.Context, w http.ResponseWriter, v error) error {
		en, ok := v.(ErrorNamer)
		if !ok {
			return encodeError(ctx, w, v)
		}
		switch en.ErrorName() {
		case "NotFound":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewResetPasswordNotFoundResponseBody(res)
			}
			w.Header().Set("goa-error", "NotFound")
			w.WriteHeader(http.StatusNotFound)
			return enc.Encode(body)
		case "BadRequest":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewResetPasswordBadRequestResponseBody(res)
			}
			w.Header().Set("goa-error", "BadRequest")
			w.WriteHeader(http.StatusBadRequest)
			return enc.Encode(body)
		default:
			return encodeError(ctx, w, v)
		}
	}
}

// EncodeChangePasswordResponse returns an encoder for responses returned by
// the user_service changePassword endpoint.
func EncodeChangePasswordResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*userserviceviews.Userresult)
		enc := encoder(ctx, w)
		body := NewChangePasswordResponseBody(res.Projected)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeChangePasswordRequest returns a decoder for requests sent to the
// user_service changePassword endpoint.
func DecodeChangePasswordRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			body ChangePasswordRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}
		err = ValidateChangePasswordRequestBody(&body)
		if err != nil {
			return nil, err
		}

		var (
			tenant string
			token  string
		)
		tenant = r.Header.Get("tenant")
		if tenant == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("tenant", "header"))
		}
		token = r.Header.Get("Authorization")
		if token == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("Authorization", "header"))
		}
		if err != nil {
			return nil, err
		}
		payload := NewChangePasswordPayload(&body, tenant, token)
		if strings.Contains(payload.Token, " ") {
			// Remove authorization scheme prefix (e.g. "Bearer")
			cred := strings.SplitN(payload.Token, " ", 2)[1]
			payload.Token = cred
		}

		return payload, nil
	}
}

// EncodeChangePasswordError returns an encoder for errors returned by the
// changePassword user_service endpoint.
func EncodeChangePasswordError(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder, formatter func(err error) goahttp.Statuser) func(context.Context, http.ResponseWriter, error) error {
	encodeError := goahttp.ErrorEncoder(encoder, formatter)
	return func(ctx context.Context, w http.ResponseWriter, v error) error {
		en, ok := v.(ErrorNamer)
		if !ok {
			return encodeError(ctx, w, v)
		}
		switch en.ErrorName() {
		case "NotFound":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewChangePasswordNotFoundResponseBody(res)
			}
			w.Header().Set("goa-error", "NotFound")
			w.WriteHeader(http.StatusNotFound)
			return enc.Encode(body)
		case "BadRequest":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewChangePasswordBadRequestResponseBody(res)
			}
			w.Header().Set("goa-error", "BadRequest")
			w.WriteHeader(http.StatusBadRequest)
			return enc.Encode(body)
		default:
			return encodeError(ctx, w, v)
		}
	}
}

// EncodeLoginResponse returns an encoder for responses returned by the
// user_service login endpoint.
func EncodeLoginResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*userserviceviews.Userresult)
		enc := encoder(ctx, w)
		body := NewLoginResponseBody(res.Projected)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeLoginRequest returns a decoder for requests sent to the user_service
// login endpoint.
func DecodeLoginRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			body LoginRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}
		err = ValidateLoginRequestBody(&body)
		if err != nil {
			return nil, err
		}

		var (
			tenant string
		)
		tenant = r.Header.Get("tenant")
		if tenant == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("tenant", "header"))
		}
		if err != nil {
			return nil, err
		}
		payload := NewLoginPayload(&body, tenant)

		return payload, nil
	}
}

// EncodeLoginError returns an encoder for errors returned by the login
// user_service endpoint.
func EncodeLoginError(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder, formatter func(err error) goahttp.Statuser) func(context.Context, http.ResponseWriter, error) error {
	encodeError := goahttp.ErrorEncoder(encoder, formatter)
	return func(ctx context.Context, w http.ResponseWriter, v error) error {
		en, ok := v.(ErrorNamer)
		if !ok {
			return encodeError(ctx, w, v)
		}
		switch en.ErrorName() {
		case "NotFound":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewLoginNotFoundResponseBody(res)
			}
			w.Header().Set("goa-error", "NotFound")
			w.WriteHeader(http.StatusNotFound)
			return enc.Encode(body)
		case "BadRequest":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewLoginBadRequestResponseBody(res)
			}
			w.Header().Set("goa-error", "BadRequest")
			w.WriteHeader(http.StatusBadRequest)
			return enc.Encode(body)
		default:
			return encodeError(ctx, w, v)
		}
	}
}

// EncodeRefreshAccessTokenResponse returns an encoder for responses returned
// by the user_service refreshAccessToken endpoint.
func EncodeRefreshAccessTokenResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*userserviceviews.Userresult)
		enc := encoder(ctx, w)
		body := NewRefreshAccessTokenResponseBody(res.Projected)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeRefreshAccessTokenRequest returns a decoder for requests sent to the
// user_service refreshAccessToken endpoint.
func DecodeRefreshAccessTokenRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			tenant string
			token  string
			err    error
		)
		tenant = r.Header.Get("tenant")
		if tenant == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("tenant", "header"))
		}
		token = r.Header.Get("Authorization")
		if token == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("Authorization", "header"))
		}
		if err != nil {
			return nil, err
		}
		payload := NewRefreshAccessTokenPayload(tenant, token)
		if strings.Contains(payload.Token, " ") {
			// Remove authorization scheme prefix (e.g. "Bearer")
			cred := strings.SplitN(payload.Token, " ", 2)[1]
			payload.Token = cred
		}

		return payload, nil
	}
}

// EncodeRefreshAccessTokenError returns an encoder for errors returned by the
// refreshAccessToken user_service endpoint.
func EncodeRefreshAccessTokenError(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder, formatter func(err error) goahttp.Statuser) func(context.Context, http.ResponseWriter, error) error {
	encodeError := goahttp.ErrorEncoder(encoder, formatter)
	return func(ctx context.Context, w http.ResponseWriter, v error) error {
		en, ok := v.(ErrorNamer)
		if !ok {
			return encodeError(ctx, w, v)
		}
		switch en.ErrorName() {
		case "NotFound":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewRefreshAccessTokenNotFoundResponseBody(res)
			}
			w.Header().Set("goa-error", "NotFound")
			w.WriteHeader(http.StatusNotFound)
			return enc.Encode(body)
		case "BadRequest":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewRefreshAccessTokenBadRequestResponseBody(res)
			}
			w.Header().Set("goa-error", "BadRequest")
			w.WriteHeader(http.StatusBadRequest)
			return enc.Encode(body)
		default:
			return encodeError(ctx, w, v)
		}
	}
}

// EncodeLogoutResponse returns an encoder for responses returned by the
// user_service logout endpoint.
func EncodeLogoutResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*userservice.MessageResult)
		enc := encoder(ctx, w)
		body := NewLogoutResponseBody(res)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeLogoutRequest returns a decoder for requests sent to the user_service
// logout endpoint.
func DecodeLogoutRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			tenant string
			token  string
			err    error
		)
		tenant = r.Header.Get("tenant")
		if tenant == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("tenant", "header"))
		}
		token = r.Header.Get("Authorization")
		if token == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("Authorization", "header"))
		}
		if err != nil {
			return nil, err
		}
		payload := NewLogoutPayload(tenant, token)
		if strings.Contains(payload.Token, " ") {
			// Remove authorization scheme prefix (e.g. "Bearer")
			cred := strings.SplitN(payload.Token, " ", 2)[1]
			payload.Token = cred
		}

		return payload, nil
	}
}

// EncodeLogoutError returns an encoder for errors returned by the logout
// user_service endpoint.
func EncodeLogoutError(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder, formatter func(err error) goahttp.Statuser) func(context.Context, http.ResponseWriter, error) error {
	encodeError := goahttp.ErrorEncoder(encoder, formatter)
	return func(ctx context.Context, w http.ResponseWriter, v error) error {
		en, ok := v.(ErrorNamer)
		if !ok {
			return encodeError(ctx, w, v)
		}
		switch en.ErrorName() {
		case "NotFound":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewLogoutNotFoundResponseBody(res)
			}
			w.Header().Set("goa-error", "NotFound")
			w.WriteHeader(http.StatusNotFound)
			return enc.Encode(body)
		case "BadRequest":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewLogoutBadRequestResponseBody(res)
			}
			w.Header().Set("goa-error", "BadRequest")
			w.WriteHeader(http.StatusBadRequest)
			return enc.Encode(body)
		default:
			return encodeError(ctx, w, v)
		}
	}
}

// EncodeListUsersResponse returns an encoder for responses returned by the
// user_service listUsers endpoint.
func EncodeListUsersResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res := v.(*userservice.ListUsersResult)
		enc := encoder(ctx, w)
		body := NewListUsersResponseBody(res)
		w.WriteHeader(http.StatusOK)
		return enc.Encode(body)
	}
}

// DecodeListUsersRequest returns a decoder for requests sent to the
// user_service listUsers endpoint.
func DecodeListUsersRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			body ListUsersRequestBody
			err  error
		)
		err = decoder(r).Decode(&body)
		if err != nil {
			if err == io.EOF {
				return nil, goa.MissingPayloadError()
			}
			return nil, goa.DecodePayloadError(err.Error())
		}

		var (
			tenant string
			token  string
		)
		tenant = r.Header.Get("tenant")
		if tenant == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("tenant", "header"))
		}
		token = r.Header.Get("Authorization")
		if token == "" {
			err = goa.MergeErrors(err, goa.MissingFieldError("Authorization", "header"))
		}
		if err != nil {
			return nil, err
		}
		payload := NewListUsersPayload(&body, tenant, token)
		if strings.Contains(payload.Token, " ") {
			// Remove authorization scheme prefix (e.g. "Bearer")
			cred := strings.SplitN(payload.Token, " ", 2)[1]
			payload.Token = cred
		}

		return payload, nil
	}
}

// EncodeListUsersError returns an encoder for errors returned by the listUsers
// user_service endpoint.
func EncodeListUsersError(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder, formatter func(err error) goahttp.Statuser) func(context.Context, http.ResponseWriter, error) error {
	encodeError := goahttp.ErrorEncoder(encoder, formatter)
	return func(ctx context.Context, w http.ResponseWriter, v error) error {
		en, ok := v.(ErrorNamer)
		if !ok {
			return encodeError(ctx, w, v)
		}
		switch en.ErrorName() {
		case "NotFound":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewListUsersNotFoundResponseBody(res)
			}
			w.Header().Set("goa-error", "NotFound")
			w.WriteHeader(http.StatusNotFound)
			return enc.Encode(body)
		case "BadRequest":
			res := v.(*goa.ServiceError)
			enc := encoder(ctx, w)
			var body interface{}
			if formatter != nil {
				body = formatter(res)
			} else {
				body = NewListUsersBadRequestResponseBody(res)
			}
			w.Header().Set("goa-error", "BadRequest")
			w.WriteHeader(http.StatusBadRequest)
			return enc.Encode(body)
		default:
			return encodeError(ctx, w, v)
		}
	}
}

// marshalUserserviceviewsUserroleresultViewToUserroleresultResponseBody builds
// a value of type *UserroleresultResponseBody from a value of type
// *userserviceviews.UserroleresultView.
func marshalUserserviceviewsUserroleresultViewToUserroleresultResponseBody(v *userserviceviews.UserroleresultView) *UserroleresultResponseBody {
	if v == nil {
		return nil
	}
	res := &UserroleresultResponseBody{
		ID:       v.ID,
		UserID:   v.UserID,
		RoleID:   v.RoleID,
		IsActive: v.IsActive,
	}
	if v.Role != nil {
		res.Role = marshalUserserviceviewsRoleresultViewToRoleresultResponseBody(v.Role)
	}

	return res
}

// marshalUserserviceviewsRoleresultViewToRoleresultResponseBody builds a value
// of type *RoleresultResponseBody from a value of type
// *userserviceviews.RoleresultView.
func marshalUserserviceviewsRoleresultViewToRoleresultResponseBody(v *userserviceviews.RoleresultView) *RoleresultResponseBody {
	if v == nil {
		return nil
	}
	res := &RoleresultResponseBody{
		ID:        v.ID,
		Name:      v.Name,
		ServiceID: v.ServiceID,
		IsActive:  v.IsActive,
	}

	return res
}

// marshalUserserviceUserresultToUserresultResponseBody builds a value of type
// *UserresultResponseBody from a value of type *userservice.Userresult.
func marshalUserserviceUserresultToUserresultResponseBody(v *userservice.Userresult) *UserresultResponseBody {
	if v == nil {
		return nil
	}
	res := &UserresultResponseBody{
		ID:           v.ID,
		Email:        v.Email,
		Name:         v.Name,
		IsVerified:   v.IsVerified,
		IsActive:     v.IsActive,
		HasAgreed:    v.HasAgreed,
		AccessToken:  v.AccessToken,
		RefreshToken: v.RefreshToken,
	}
	if v.Roles != nil {
		res.Roles = make([]*UserroleresultResponseBody, len(v.Roles))
		for i, val := range v.Roles {
			res.Roles[i] = marshalUserserviceUserroleresultToUserroleresultResponseBody(val)
		}
	}

	return res
}

// marshalUserserviceUserroleresultToUserroleresultResponseBody builds a value
// of type *UserroleresultResponseBody from a value of type
// *userservice.Userroleresult.
func marshalUserserviceUserroleresultToUserroleresultResponseBody(v *userservice.Userroleresult) *UserroleresultResponseBody {
	if v == nil {
		return nil
	}
	res := &UserroleresultResponseBody{
		ID:       v.ID,
		UserID:   v.UserID,
		RoleID:   v.RoleID,
		IsActive: v.IsActive,
	}
	if v.Role != nil {
		res.Role = marshalUserserviceRoleresultToRoleresultResponseBody(v.Role)
	}

	return res
}

// marshalUserserviceRoleresultToRoleresultResponseBody builds a value of type
// *RoleresultResponseBody from a value of type *userservice.Roleresult.
func marshalUserserviceRoleresultToRoleresultResponseBody(v *userservice.Roleresult) *RoleresultResponseBody {
	if v == nil {
		return nil
	}
	res := &RoleresultResponseBody{
		ID:        v.ID,
		Name:      v.Name,
		ServiceID: v.ServiceID,
		IsActive:  v.IsActive,
	}

	return res
}

// marshalUserservicePageinfoToPageinfoResponseBody builds a value of type
// *PageinfoResponseBody from a value of type *userservice.Pageinfo.
func marshalUserservicePageinfoToPageinfoResponseBody(v *userservice.Pageinfo) *PageinfoResponseBody {
	if v == nil {
		return nil
	}
	res := &PageinfoResponseBody{
		PageNumber: v.PageNumber,
		PageSize:   v.PageSize,
		Count:      v.Count,
		TotalCount: v.TotalCount,
	}

	return res
}

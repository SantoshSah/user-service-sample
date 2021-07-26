package design

import (
	. "goa.design/goa/v3/dsl"
	cors "goa.design/plugins/v3/cors/dsl"
)

var _ = API("userapi", func() {
	Title("user Service")
	Version("1.0.0")
	Description("Service for managing users")
	Docs(func() { // Documentation links
		Description("doc description")
		URL("doc URL")
	})
	HTTP(func() {
		Headers(func() {
			Header("tenant", String, "Tenant Header Name", func() {
				Enum("tenant1", "tenant2")
			})
			Required("tenant")
		})
	})
	Server("user_server", func() {
		Host("localhost", func() {
			URI("http://0.0.0.0:8120")
			URI("grpc://0.0.0.0:8121")
		})
	})
})

//JWT : for JWT Security
var JWT = JWTSecurity("jwt", func() {
	Scope("system:write", "Write to the system")
	Scope("system:read", "Read anything in there")
})

// UserResult : return resultset for signup
var UserResult = ResultType("UserResult", func() {
	Field(1, "id", String, "User UUID")
	Field(2, "email", String, "User email")
	Field(3, "name", String, "User name")
	Field(4, "isVerified", Boolean, "If user has been verified")
	Field(5, "isActive", Boolean, "If user is active")
	Field(6, "hasAgreed", Boolean, "If user has agreed terms & conditions")
	Field(7, "accessToken", String, "AccessToken to authenticate user for next processes")
	Field(8, "refreshToken", String, "RefreshToken to refresh auth token")
	Field(9, "roles", CollectionOf(UserRoleResult), "User roles")
})

// RoleResult :  result type for roles
var RoleResult = ResultType("RoleResult", func() {
	Field(1, "id", String, "role UUID")
	Field(2, "name", String, "role name")
	Field(3, "serviceId", String, "service UUID the role belongs to")
	Field(4, "isActive", Boolean, "If record is active")
})

// UserRoleResult :  result type for UserRoles
var UserRoleResult = ResultType("UserRoleResult", func() {
	Field(1, "id", String, "UserRole UUID")
	Field(2, "userID", String, "User UUID")
	Field(3, "roleID", String, "Role UUID")
	Field(4, "isActive", Boolean, "If record is active")
	Field(5, "role", RoleResult, "role detail")
})

// MessageResult :  message result for success or error
var MessageResult = Type("MessageResult", func() {
	Field(1, "type", String, "Message type i.e. SUCCESS, ERROR")
	Field(2, "desc", String, "Message description")
})

// PageInfo : The object that specifies all the criteria used for pagination
var PageInfo = ResultType("PageInfo", func() {
	Field(1, "pageNumber", Int, "Page Number for returned resultset")
	Field(2, "pageSize", Int, "Page size for returned resultset")
	Field(3, "count", Int, "Count of returned record set")
	Field(4, "totalCount", Int64, "Total Count for this query")
})

var _ = Service("user_service", func() {
	Description("The user service manages users.")
	cors.Origin("*", func() {
		//cors.Headers("Accept", "Content-Type", "DNT", "Referer", "keep-alive", "user-agent", "cache-control", "content-type", "content-transfer-encoding", "custom-header-1", "x-accept-content-transfer-encoding", "x-accept-response-streaming", "x-user-agent", "x-grpc-web", "grpc-timeout") // One or more authorized headers, use "*" to authorize all
		cors.Headers("authorization", "tenant", "content-type", "x-grpc-web", "x-user-agent")
		cors.Methods("GET", "PUT", "DELETE", "POST", "OPTIONS") // One or more authorized HTTP methods
		cors.Expose("grpc-status", " grpc-message")             // One or more headers exposed to clients
		cors.MaxAge(600)                                        // How long to cache a preflight request response
		cors.Credentials()                                      // Sets Access-Control-Allow-Credentials header
	})

	Method("signup", func() {
		Payload(func() {
			Field(1, "email", String, "User email address")
			Field(2, "tenant", String, "Tenant Header Name")
			Required("email")
		})

		Result(UserResult)
		Error("NotFound")
		Error("BadRequest")

		// HTTP transport
		HTTP(func() {
			POST("/signup")
			Response(StatusOK)
			Response("NotFound", StatusNotFound)
			Response("BadRequest", StatusBadRequest)
		})

		GRPC(func() {
			Response(CodeOK)
			Response("NotFound", CodeNotFound)
			Response("BadRequest", CodeInvalidArgument)
		})
	})

	Method("verifyConfirmationToken", func() {
		Payload(func() {
			Field(1, "userId", String, "UserId")
			Field(2, "confirmationToken", UInt64, "Confirmation token")
			Field(3, "tenant", String, "Tenant Header Name")
			Required("userId", "confirmationToken")
		})

		Result(UserResult)
		Error("NotFound")
		Error("BadRequest")

		// HTTP transport
		HTTP(func() {
			POST("/verifyConfirmationToken")
			Response(StatusOK)
			Response("NotFound", StatusNotFound)
			Response("BadRequest", StatusBadRequest)
		})

		GRPC(func() {
			Response(CodeOK)
			Response("NotFound", CodeNotFound)
			Response("BadRequest", CodeInvalidArgument)
		})
	})

	Method("updateUsername", func() {
		Security(JWT)
		Payload(func() {
			TokenField(1, "token", String, "JWT token used to perform authorization")
			Field(2, "name", String, "User name")
			Field(3, "tenant", String, "Tenant Header Name")
			Required("token", "name")
		})

		Result(UserResult)
		Error("NotFound")
		Error("BadRequest")

		HTTP(func() {
			// The "Authorization" header is defined implicitly.
			POST("/updateUsername")
			Response(StatusOK)
			Response("NotFound", StatusNotFound)
			Response("BadRequest", StatusBadRequest)
		})

		GRPC(func() {
			Response(CodeOK)
			Response("NotFound", CodeNotFound)
			Response("BadRequest", CodeInvalidArgument)
		})
	})

	Method("verifyPasswordResetToken", func() {
		Payload(func() {
			Field(1, "userId", String, "UserId")
			Field(2, "passwordResetToken", UInt64, "Password reset token")
			Field(3, "tenant", String, "Tenant Header Name")
			Required("userId", "passwordResetToken")
		})

		Result(UserResult)
		Error("NotFound")
		Error("BadRequest")

		// HTTP transport
		HTTP(func() {
			POST("/verifyPasswordResetToken")
			Response(StatusOK)
			Response("NotFound", StatusNotFound)
			Response("BadRequest", StatusBadRequest)
		})

		GRPC(func() {
			Response(CodeOK)
			Response("NotFound", CodeNotFound)
			Response("BadRequest", CodeInvalidArgument)
		})
	})

	Method("resetPassword", func() {
		Payload(func() {
			Field(1, "email", String, "User email")
			Field(2, "tenant", String, "Tenant Header Name")
			Required("email")
		})

		Result(UserResult)
		Error("NotFound")
		Error("BadRequest")

		HTTP(func() {
			POST("/resetPassword")
			Response(StatusOK)
			Response("NotFound", StatusNotFound)
			Response("BadRequest", StatusBadRequest)
		})

		GRPC(func() {
			Response(CodeOK)
			Response("NotFound", CodeNotFound)
			Response("BadRequest", CodeInvalidArgument)
		})
	})

	Method("changePassword", func() {
		Security(JWT)
		Payload(func() {
			TokenField(1, "token", String, "JWT token used to perform authorization")
			Field(2, "password", String, "User password")
			Field(3, "tenant", String, "Tenant Header Name")
			Required("token", "password")
		})

		Result(UserResult)
		Error("NotFound")
		Error("BadRequest")

		HTTP(func() {
			// The "Authorization" header is defined implicitly.
			POST("/changePassword")
			Response(StatusOK)
			Response("NotFound", StatusNotFound)
			Response("BadRequest", StatusBadRequest)
		})

		GRPC(func() {
			Response(CodeOK)
			Response("NotFound", CodeNotFound)
			Response("BadRequest", CodeInvalidArgument)
		})
	})

	Method("login", func() {
		Payload(func() {
			Field(1, "email", String, "User email")
			Field(2, "password", String, "User password")
			Field(3, "tenant", String, "Tenant Header Name")
			Required("email", "password")
		})

		Result(UserResult)
		Error("NotFound")
		Error("BadRequest")

		HTTP(func() {
			// The "Authorization" header is defined implicitly.
			POST("/login")
			Response(StatusOK)
			Response("NotFound", StatusNotFound)
			Response("BadRequest", StatusBadRequest)
		})

		GRPC(func() {
			Response(CodeOK)
			Response("NotFound", CodeNotFound)
			Response("BadRequest", CodeInvalidArgument)
		})
	})

	Method("refreshAccessToken", func() {
		Security(JWT)
		Payload(func() {
			TokenField(1, "token", String, "JWT token used to perform authorization")
			Field(2, "tenant", String, "Tenant Header Name")
			Required("token")
		})

		Result(UserResult)
		Error("NotFound")
		Error("BadRequest")

		HTTP(func() {
			// The "Authorization" header is defined implicitly.
			POST("/refreshAccessToken")
			Response(StatusOK)
			Response("NotFound", StatusNotFound)
			Response("BadRequest", StatusBadRequest)
		})

		GRPC(func() {
			Response(CodeOK)
			Response("NotFound", CodeNotFound)
			Response("BadRequest", CodeInvalidArgument)
		})
	})

	Method("logout", func() {
		Security(JWT)
		Payload(func() {
			TokenField(1, "token", String, "JWT token used to perform authorization")
			Field(2, "tenant", String, "Tenant Header Name")
			Required("token")
		})

		Result(MessageResult)
		Error("NotFound")
		Error("BadRequest")

		HTTP(func() {
			POST("/logout")
			Response(StatusOK)
			Response("NotFound", StatusNotFound)
			Response("BadRequest", StatusBadRequest)
		})

		GRPC(func() {
			Response(CodeOK)
			Response("NotFound", CodeNotFound)
			Response("BadRequest", CodeInvalidArgument)
		})
	})

	Method("listUsers", func() {
		Security(JWT)
		Payload(func() {
			TokenField(1, "token", String, "JWT token used to perform authorization")
			Field(2, "email", String, "User email for search")
			Field(3, "mobileNumber", String, "User mobile number for search")
			Field(4, "name", String, "User name for search")
			Field(6, "isActive", String, "If user is active")
			Field(7, "isVerified", String, "If user is verified")
			Field(8, "hasAgreed", String, "If user has agreed")
			Field(9, "role", String, "User Role")
			Field(10, "pageNumber", Int, "Page Number for search")
			Field(11, "pageSize", Int, "pageSize per page")
			Field(13, "tenant", String, "Tenant Header Name")
			Required("token")
		})

		Result(func() {
			Field(1, "results", CollectionOf(UserResult), "User Results")
			Field(2, "pageInfo", PageInfo, "Pagination information")
		})
		Error("NotFound")
		Error("BadRequest")

		HTTP(func() {
			POST("/listUsers")
			Response(StatusOK)
			Response("NotFound", StatusNotFound)
			Response("BadRequest", StatusBadRequest)
		})

		GRPC(func() {
			Response(CodeOK)
			Response("NotFound", CodeNotFound)
			Response("BadRequest", CodeInvalidArgument)
		})
	})

	Files("/openapi.yaml", "./gen/http/openapi.yaml")
})

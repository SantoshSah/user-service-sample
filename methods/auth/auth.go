package auth

import (
	"crypto/rand"
	"io"
	"os"
	"strconv"
	"time"

	db "github.com/SantoshSah/user-service-sample/methods/dbs"
	"github.com/SantoshSah/user-service-sample/types"
	"github.com/dgrijalva/jwt-go"
	redis "github.com/go-redis/redis/v8"
)

var (
	numberTable = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9'}

	//RefreshTokenJwtKey is JWTKey for refresh token
	RefreshTokenJwtKey = []byte(os.Getenv("JWT_REFRESH_SECRET"))

	//AccessTokenJwtKey is JWTKey for access token
	AccessTokenJwtKey = []byte(os.Getenv("JWT_ACCESS_SECRET"))

	//InvitationTokenJwtKey is JWTKey for invitation token
	InvitationTokenJwtKey = []byte(os.Getenv("JWT_INVITATION_SECRET"))
)

//IsBlacklisted check if access token is blacklisted
func IsBlacklisted(token string) (bool, error) {
	shortToken := token[len(token)-50:]
	_, err := db.RedisClient.Get(db.RedisClient.Context(), shortToken).Result()

	//check if key exists
	if err == redis.Nil {
		return false, nil
	} else if err != nil {
		return true, err
	}

	return true, nil
}

//Blacklist marks user as black list when logged out
func Blacklist(token string) (err error) {
	accessTokenExpirationMin, err := strconv.ParseInt(os.Getenv("ACCESS_TOKEN_EXPIRATION_MIN"), 10, 64)
	shortToken := token[len(token)-50:]
	status := db.RedisClient.Set(db.RedisClient.Context(), shortToken, "Logged Out", time.Duration(accessTokenExpirationMin)*time.Minute)
	_, err = status.Result()

	if err != nil {
		return err
	}
	return nil
}

//Whitelist remove user from black list when logged in
func Whitelist(token string) (err error) {
	status := db.RedisClient.Del(db.RedisClient.Context(), token)
	_, err = status.Result()

	if err != nil {
		return err
	}
	return nil
}

//GenerateConfirmationToken generate confirmation token
func GenerateConfirmationToken() (token uint64) {
	numberOfDigit := 6
	b := make([]byte, numberOfDigit)
	n, err := io.ReadAtLeast(rand.Reader, b, numberOfDigit)
	if n != numberOfDigit {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = numberTable[int(b[i])%len(numberTable)]
	}

	t, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		panic(err)
	}

	return t
}

//GetConfirmationTokenExpirationTime returns expiration time for tokens
func GetConfirmationTokenExpirationTime() time.Time {
	tokenExpirationTimeMin, _ := strconv.ParseInt(os.Getenv("CONFIRMATION_TOKEN_EXPIRATION_MIN"), 10, 64)
	//return time.Now().UTC().Add(time.Minute * time.Duration(tokenExpirationTimeMin))
	return time.Now().Add(time.Minute * time.Duration(tokenExpirationTimeMin))
}

//GenerateAccessToken generate access token
func GenerateAccessToken(user types.User, tempAccess bool) (string, error) {
	//TODO:: Invalidate all previous Auth Token for user

	// Declare the expiration time of the token. Currently set to 365 days
	accessTokenExpirationMin, err := strconv.ParseInt(os.Getenv("ACCESS_TOKEN_EXPIRATION_MIN"), 10, 64)
	if tempAccess == true {
		accessTokenExpirationMin, err = strconv.ParseInt(os.Getenv("ACCESS_TOKEN_TEMP_EXPIRATION_MIN"), 10, 64)
	}

	if err != nil {
		return "", err
	}

	expirationTime := time.Now().Add(time.Minute * time.Duration(accessTokenExpirationMin))

	// Create the JWT claims, which includes the username and expiry time
	claims := &types.JWTClaims{
		UserID:    user.ID,
		Username:  user.Name,
		UserEmail: user.Email,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// token.Header["kid"] = "signin_1"

	// Create the JWT string
	tokenString, _ := token.SignedString(AccessTokenJwtKey)

	return tokenString, err
}

//generateRefreshToken generate refresh token
func generateRefreshToken(user types.User) (string, error) {
	refreshTokenExpirationMin, err := strconv.ParseInt(os.Getenv("REFRESH_TOKEN_EXPIRATION_MIN"), 10, 64)

	if err != nil {
		return "", err
	}

	expirationTime := time.Now().Add(time.Minute * time.Duration(refreshTokenExpirationMin))

	// Create the JWT claims, which includes the username and expiry time
	claims := &types.JWTClaims{
		UserID:    user.ID,
		Username:  user.Name,
		UserEmail: user.Email,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// refreshToken.Header["kid"] = "signin_2"

	// Create the JWT string
	tokenString, _ := refreshToken.SignedString(RefreshTokenJwtKey)

	return tokenString, err
}

// GenerateTokenPair creates and returns a new set of access_token and refresh_token.
func GenerateTokenPair(u types.User) (string, string, error) {
	tokenString, err := GenerateAccessToken(u, false)
	if err != nil {
		return "", "", err
	}

	refreshTokenString, err := generateRefreshToken(u)
	if err != nil {
		return "", "", err
	}

	return tokenString, refreshTokenString, nil
}

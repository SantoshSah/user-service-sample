package types

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"
)

//JWTClaims : claims for JWT Authentication
type JWTClaims struct {
	UserID    string `json:"userID"`
	Username  string `json:"username"`
	UserEmail string `json:"userEmail"`
	jwt.StandardClaims
}

//User : type for users
type User struct {
	ID                         string         `json:"ID" gorm:"type:UUID;NOT NULL;DEFAULT:gen_random_uuid()"`
	Name                       string         `json:"name"`
	Email                      string         `json:"email"`
	MobileNumber               string         `json:"mobileNumber"`
	Password                   string         `json:"password"`
	ConfirmationToken          uint64         `json:"confirmationToken"`
	ConfirmationTokenExpiresAt time.Time      `json:"confirmationTokenExpiresAt,omitempty"`
	IsVerified                 bool           `json:"isVerified"`
	Image                      string         `json:"image"`
	IsActive                   bool           `json:"isActive"`
	HasAgreed                  bool           `json:"hasAgreed"`
	CreatedAt                  time.Time      `json:"createdAt" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt                  time.Time      `json:"updatedAt" gorm:"not null;default:CURRENT_TIMESTAMP"`
	DeletedAt                  gorm.DeletedAt `json:"deletedAt" gorm:"default:NULL"`
	HasSubscribed              bool           `json:"hasSubscribed" gorm:"not null;default:false"`
	UnsubscribedReasons        string         `json:"unsubscribedReasons"`
}

package models

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/mohammedfuta2000/csrf-project/randomstrings"
)


type User struct{
	UserName, PasswordHash, Role string
}

type TokenClaims struct{
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

const RefreshTokenValidTime = time.Hour*72
const AuthTokenValidTime = time.Minute*15

func GenerateCSRFSecret()(string,error){
	return randomstrings.GenerateRandomString(32)
}
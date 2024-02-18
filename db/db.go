package db

import (
	"errors"
	"log"

	"github.com/mohammedfuta2000/csrf-project/db/models"
	"github.com/mohammedfuta2000/csrf-project/randomstrings"
	"golang.org/x/crypto/bcrypt"
)

var users = map[string]models.User{}
var refreshTokens map[string]string

func InitDB() {
	refreshTokens = make(map[string]string)
}
func StoreUser(username, password, role string) (uuid string, err error) {
	uuid, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	// absolute bonkers
	u := models.User{}
	for u != users[uuid] {
		uuid, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return "", err
		}
	}

	passwordHash, hashErr := GenerateBcryptHash(password)
	if hashErr != nil {
		err = hashErr
		return
	}
	users[uuid] = models.User{UserName: username, PasswordHash: passwordHash, Role: role}
	return uuid, err
}

func DeleteUser(uuid string) {
	delete(users, uuid)
}

func FetchUserById(uuid string) (models.User, error) {
	u := users[uuid]
	blankUser := models.User{}

	if blankUser != u {
		return u, nil
	} else {
		return u, errors.New("User not found that matches given uuid")
	}
}

func FetchUserByUserName(userName string) (models.User, string, error) {
	for k, v := range users {
		if v.UserName == userName {
			return v, k, nil
		}

	}
	return models.User{}, "", errors.New("user not found that mathces")
}

func DeleteRefreshToken(jti string) {
	delete(refreshTokens, jti)
}
// bonkers
func StoreRefreshToken() (jti string, err error) {
	jti, err= randomstrings.GenerateRandomString(32)
	if err!=nil {
		return jti,err
	}

	for refreshTokens[jti] != ""{
		jti,err=randomstrings.GenerateRandomString(32)
		if err!=nil {
			return jti,err
		}
	}
	refreshTokens[jti] = "valid"

	return jti,err 
}

func CheckRefreshToken(jti string) bool {
	return refreshTokens[jti]!=""
}

func LogUserIn(username, password string)(models.User, string, error) {
	user,uuid,userErr:= FetchUserByUserName(username)
	log.Println(user,uuid,userErr)
	if userErr!= nil {
		return models.User{}, "",userErr
	}
	return user, uuid, CheckPasswordAgainstHash(user.PasswordHash, password)
}

func GenerateBcryptHash(password string)(string,error) {
	
	hash,err:=bcrypt.GenerateFromPassword([]byte(password),bcrypt.DefaultCost)
	// ??
	return string(hash[:]), err
}

func CheckPasswordAgainstHash(hash,password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash),[]byte(password))
}

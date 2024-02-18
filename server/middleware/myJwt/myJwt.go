package myJwt

import (
	"crypto/rsa"
	"errors"
	"log"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mohammedfuta2000/csrf-project/db"
	"github.com/mohammedfuta2000/csrf-project/db/models"
)

const (
	priKeyPath = "keys/app.rsa"
	pubKeyPath = "keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func InitJwt() error {
	signBytes, err := os.ReadFile(priKeyPath)
	if err != nil {
		return err
	}
	// jwt.ParseRSAPrivateKeyFromPEMWithPassword()
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}
	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}
	return nil
}
func CreateNewTokens(uuid, role string) (authTokenString, refreshTokenString, csrfToken string, err error) {
	// generate csrf secret, refresh and auth tokens
	csrfSecret, err := models.GenerateCSRFSecret()
	if err != nil {
		return
	}

	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
	return

}
func CheckAndRefreshingTokens(oldAuthTokenString, oldRefreshTokenString, oldCsrfsecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error) {
	if oldCsrfsecret == "" {
		log.Println("NO CSRF token")
		err = errors.New("Unauthorized")
		return
	}
	authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	if oldCsrfsecret != authTokenClaims.Csrf {
		log.Println("CSRF token doesn't match jwt!")
		err = errors.New("Unauthorized")
		return
	}

	if authToken.Valid {
		log.Println("AuthToken is valid")

		newCsrfSecret = authTokenClaims.Csrf
		newRefreshTokenString, err = updateRefreshTokenExp(oldAuthTokenString)
		newAuthTokenString = oldAuthTokenString
		return
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		log.Println("Auth Token is not valid")
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			log.Println("AuthToken is expired")

			newAuthTokenString, newCsrfSecret, err = updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)

			if err != nil {
				return
			}
			newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
			if err != nil {
				return
			}

			newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
			if err != nil {
				return
			}
			return
		} else {
			log.Println("error in auth token")
			err = errors.New("error in auth token")
			return
		}
	} else {
		log.Println("error in auth token")
		err = errors.New("error in auth token")
		return
	}
	// err = errors.New("Unauthrized")
	// return

}
func createAuthTokenString(uuid, role, csrfSecret string) (authTokenString string, err error) {
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   uuid,
			ExpiresAt: authTokenExp,
		},
		Role: role,
		Csrf: csrfSecret,
	}
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)
	authTokenString, err = authJwt.SignedString(signKey)
	return
}
func createRefreshTokenString(uuid, role, csrfString string) (refreshTokenString string, err error) {
	refreshTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	refreshJti, err := db.StoreRefreshToken()
	if err != nil {
		return
	}
	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        refreshJti,
			Subject:   uuid,
			ExpiresAt: refreshTokenExp,
		},
		Role: role,
		Csrf: csrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenString, err = refreshJwt.SignedString(signKey)
	return

}
func updateRefreshTokenExp(oldRefreshTokenString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()

	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: refreshTokenExp,
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: oldRefreshTokenClaims.Csrf,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}
func updateAuthTokenString(refreshTokenString, oldAuthTokenString string) (newAuthTokenString, csrfSecret string, err error) {
	refreshToken, _ := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("error reading jwt claims")
		return
	}

	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id) {
		if refreshToken.Valid {
			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})

			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok {
				err = errors.New("errors reading jwt claims")
				return
			}

			csrfSecret, err = models.GenerateCSRFSecret()
			if err != nil {
				return
			}

			createAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)
			return
		} else {
			log.Println("refresh token has expired")
			db.DeleteRefreshToken(refreshTokenClaims.Id)

			err = errors.New("Unauthorized")
			return
		}
	} else {
		log.Println("refresh token has expired")
		err = errors.New("Unauthorized")
		return
	}
}
func RevokeRefreshToken(refreshTokenString string) error {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return errors.New("could not parse token with claims")
	}
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return errors.New("could not parse token with claims")
	}

	db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)
	return nil

}
func updateRefreshTokenCsrf(oldRefreshTokenString, newCsrfString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}
	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.Id,
			Subject:   oldRefreshTokenClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.ExpiresAt,
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: newCsrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}
func GrabUUID(authTokenString string) (string, error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return "", errors.New("error Fetching claims")
	})
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return "", errors.New("error Fetching claims")
	}

	return authTokenClaims.StandardClaims.Subject, nil
}

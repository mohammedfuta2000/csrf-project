package middleware

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/mohammedfuta2000/csrf-project/db"
	"github.com/mohammedfuta2000/csrf-project/server/middleware/myJwt"
	"github.com/mohammedfuta2000/csrf-project/server/templates"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panic("Recovered! Panic:%v", err)
				http.Error(w, http.StatusText(500), 500)

			}
		}()
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "/logout", "/deleteUser":
			log.Println("In auth Restricted Section")
			AuthCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! no auth cookie ")
				nullifyTokenCookies(w, r)
				http.Error(w, http.StatusText(401), 401)
				return
			} else if authErr != nil {
				log.Panic("panic: %v", authErr)
				nullifyTokenCookies(w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			RefreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! no refresh cookie ")
				nullifyTokenCookies(w, r)
				http.Redirect(w, r, "login", 302)
				return
			} else if refreshErr != nil {
				log.Panic("panic: %v", refreshErr)
				nullifyTokenCookies(w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			requestCsrfToken := grabCsrfFromReq(r)
			log.Println(requestCsrfToken)

			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CheckAndRefreshingTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Unauthorized attempt! JWT is not valid")
					http.Error(w, http.StatusText(401), 401)
					return
				} else {
					log.Panic("err not nil")
					log.Panic("panic: %+v", err)
					http.Error(w, http.StatusText(500), 500)
					return
				}
			}
			log.Println("successfully recreated JWT")

			w.Header().Set("Access-Control-Allow-Origin", "*")
			setAuthAndRefreshCookies(w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)

		default:
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{BAlertUser: csrfSecret, AlertMsg: "hello Moh"})
	case "/login":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "login", &templates.LoginPage{BAlertUser: false, AlertMsg: ""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			user, uuid, logginErr := db.LogUserIn(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""))
			fmt.Println(user, uuid, logginErr)
			if logginErr != nil {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, user.Role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				setAuthAndRefreshCookies(w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)

				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":

		switch r.Method {
		case "GET":
			log.Println("register GET has been hit")
			templates.RenderTemplate(w, "register", &templates.RegisterPage{BAlertUser: false, AlertMsg: ""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)
			_, _, err := db.FetchUserByUserName(strings.Join(r.Form["username"], ""))
			if err == nil {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				role := "user"
				uuid, err := db.StoreUser(
					strings.Join(r.Form["username"], ""),
					strings.Join(r.Form["password"], ""),
					role,
				)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}
				log.Println("UUID: " + uuid)

				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				setAuthAndRefreshCookies(w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(w, r)
		http.Redirect(w, r, "/login", 302)

	case "/deleteUser":
		log.Println("Delete the user")

		AuthCookie, AuthErr := r.Cookie("AuthCookie")
		if AuthErr == http.ErrNoCookie {
			log.Println("Unauthorized")
			nullifyTokenCookies(w, r)
			http.Redirect(w, r, "login", 302)
			return
		} else if AuthErr != nil {
			log.Panic("panic:%+v", AuthErr)
			nullifyTokenCookies(w, r)
			http.Redirect(w, r, "login", 302)
			return
		}
		uuid, uuidErr := myJwt.GrabUUID(AuthCookie.Value)
		if uuidErr != nil {
			log.Panic("panic:%+v", uuidErr)
			nullifyTokenCookies(w, r)
			http.Redirect(w, r, "login", 302)
			return
		}
		db.DeleteUser(uuid)
		nullifyTokenCookies(w, r)
		http.Redirect(w, r, "register", 302)
		return
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func nullifyTokenCookies(w http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, &refreshCookie)

	RefreshCookie, RefreshErr := r.Cookie("RefreshToken")
	if RefreshErr == http.ErrNoCookie {
		return
	} else if RefreshErr != nil {
		log.Panic("panic: %+v", RefreshErr)
		http.Error(w, http.StatusText(500), 500)
	}
	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w http.ResponseWriter, authTokenString, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authTokenString,
		HttpOnly: true,
	}
	http.SetCookie(w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		HttpOnly: true,
	}
	http.SetCookie(w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfFromFrom := r.FormValue("X-CSRF-Token")
	if csrfFromFrom != "" {
		return csrfFromFrom
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}

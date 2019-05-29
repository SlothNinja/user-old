package user

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"bitbucket.org/SlothNinja/log"
	"cloud.google.com/go/datastore"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/appengine"
)

const (
	PORT        = "PORT"
	DefaultPort = ":8080"
	HOST        = "HOST"
	userNewPath = "/#/new"
)

func Login(path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debugf("Entering")
		defer log.Debugf("Exiting")

		session := sessions.Default(c)
		state := randToken()
		session.Set("state", state)
		session.Save()

		c.Redirect(http.StatusSeeOther, getLoginURL(c, path, state))
	}
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func getLoginURL(c *gin.Context, path, state string) string {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	// State can be some kind of random generated hash string.
	// See relevant RFC: http://tools.ietf.org/html/rfc6749#section-10.12
	return oauth2Config(c, path, scopes()...).AuthCodeURL(state)
}

func oauth2Config(c *gin.Context, path string, scopes ...string) *oauth2.Config {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	log.Debugf("request: %#v", c.Request)

	// protocol := "http"
	// if c.Request.TLS != nil {
	// 	protocol = "https"
	// }

	return &oauth2.Config{
		ClientID:     "435340145701-t5o50sjq7hsbilopgreobhvrv30e1tj4.apps.googleusercontent.com",
		ClientSecret: "Fe5f-Ht1V5_GohDEOS_TQOVc",
		Endpoint:     google.Endpoint,
		Scopes:       scopes,
		RedirectURL:  fmt.Sprintf("%s%s", getHost(), path),
	}
}

func scopes() []string {
	return []string{"email", "profile", "openid"}
}

func isDev() bool {
	return os.Getenv("DEV") == "true"
}

func getPort() string {
	port := os.Getenv(PORT)
	if port != "" {
		if strings.HasPrefix(port, ":") {
			return port
		}
		return ":" + port

	}
	port = DefaultPort
	log.Printf("Defaulting to port %s", port)
	return port
}

func getHost() string {
	if isDev() {
		return os.Getenv(HOST) + getPort()
	}
	return os.Getenv(HOST)
}

func Auth(path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debugf("Entering")
		defer log.Debugf("Exiting")

		// Handle the exchange code to initiate a transport.
		session := sessions.Default(c)
		retrievedState := session.Get("state")
		if retrievedState != c.Query("state") {
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session state: %s", retrievedState))
			return
		}

		log.Debugf("retrievedState: %#v", retrievedState)
		ac := appengine.NewContext(c.Request)
		conf := oauth2Config(c, path, scopes()...)
		tok, err := conf.Exchange(ac, c.Query("code"))
		if err != nil {
			log.Errorf("tok error: %#v", err)
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		log.Debugf("tok: %#v", tok)

		client := conf.Client(ac, tok)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		log.Debugf("body: %s", body)

		uinfo := Info{}
		var b binding.BindingBody = binding.JSON
		err = b.BindBody(body, &uinfo)
		if err != nil {
			log.Errorf("BindBody error: %v", err)
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		log.Debugf("info: %#v", uinfo)

		id := ID(uinfo.Sub)
		u, err := ByID(c, id)
		if err == datastore.ErrNoSuchEntity {
			u = New2(id)
			u.Email = uinfo.Email
			err = u.To(session)
			if err != nil {
				log.Errorf("session.Save error: %v", err)
				c.AbortWithError(http.StatusBadRequest, err)
				return
			}
			log.Debugf("session saved")
			c.Redirect(http.StatusSeeOther, userNewPath)
			return
		}

		if err != nil {
			log.Errorf("ByID => \n\t id: %s\n\t error: %s", id, err)
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		err = u.To(session)
		if err != nil {
			log.Errorf("session.Save error: %v", err)
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		log.Debugf("session saved")

		c.Redirect(http.StatusSeeOther, "/")
	}
}

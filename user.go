package user

import (
	"crypto/md5"
	"encoding/gob"
	"encoding/json"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/SlothNinja/log"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"golang.org/x/exp/errors"
	"golang.org/x/exp/errors/fmt"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
)

func init() {
	gob.Register(sessionToken{})
}

const fqdn = "www.slothninja.com"

const (
	GTMonster                    = "monsterid"
	USER_DATASTORE_PROJECT_ID    = "USER_DATASTORE_PROJECT_ID"
	USER_DATASTORE_EMULATOR_HOST = "USER_DATASTORE_EMULATOR_HOST"
)

var namespaceUUID = uuid.NewV5(uuid.NamespaceDNS, fqdn)

var (
	ErrClient       = errors.New("unable to create datastore client")
	ErrNotFound     = errors.New("user not found")
	ErrTooManyFound = errors.New("found too many users")
)

// Generates ID for User from ID obtained from OAuth OpenID Connect
func id(s string) string {
	return uuid.NewV5(namespaceUUID, s).String()
}

type Data struct {
	Name               string    `json:"name"`
	LCName             string    `json:"lcName"`
	Email              string    `json:"email"`
	GoogleID           string    `json:"googleId"`
	XMPPNotifications  bool      `json:"xmppNotifications"`
	EmailNotifications bool      `json:"emailNotifications"`
	EmailReminders     bool      `json:"emailReminders"`
	GravType           string    `json:"gravType"`
	Admin              bool      `json:"admin"`
	JoinedAt           time.Time `json:"joinedAt"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

const (
	NoID             = 0
	Kind             = "User"
	uidParam         = "uid"
	guserKey         = "guser"
	currentKey       = "current"
	userKey          = "User"
	countKey         = "count"
	homePath         = "/"
	salt             = "slothninja"
	usersKey         = "Users"
	uinfoKey         = "user-info"
	sessionKey       = "session"
	NotFound   int64 = -1
)

type Info struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	LoggedIn      bool
	Admin         bool
}

func emailHash(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	hash := md5.New()
	_, err := hash.Write([]byte(email))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

var None = User{}

func current(c *gin.Context) User {
	u, ok := c.Value(currentKey).(User)
	if !ok {
		return None
	}
	return u
}

func withCurrent(c *gin.Context, u User) {
	c.Set(currentKey, u)
}

type User struct {
	Key     *datastore.Key `datastore:"__key__" json:"key"`
	User0ID int64          `json:"user0id"`
	User1ID string         `json:"user1id"`
	Data
}

func (u User) ID() string {
	if u.Key == nil {
		return ""
	}
	return u.Key.Name
}

func (u User) MarshalJSON() ([]byte, error) {
	hash, err := emailHash(u.Email)
	if err != nil {
		return nil, err
	}

	type u2 User
	return json.Marshal(struct {
		EmailHash string `json:"emailHash"`
		ID        string `json:"id"`
		u2
	}{
		EmailHash: hash,
		ID:        u.ID(),
		u2:        u2(u),
	})
}

func New(id string) User {
	return User{Key: newKey(id)}
}

func newKey(id string) *datastore.Key {
	return datastore.NameKey(Kind, id, nil)
}

func InfoFrom(s sessions.Session) (Info, bool) {
	uinfo, ok := s.Get(uinfoKey).(Info)
	return uinfo, ok
}

func NameFrom(email string) string {
	return strings.Split(email, "@")[0]
}

func lcName(email string) string {
	return strings.ToLower(NameFrom(email))
}

type sessionToken struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (u User) SaveTo(s sessions.Session) error {
	s.Set(sessionKey, sessionToken{ID: u.ID(), Email: u.Email})
	return s.Save()
}

func SessionTokenFrom(s sessions.Session) (sessionToken, bool) {
	token, ok := s.Get(sessionKey).(sessionToken)
	return token, ok
}

func Client(c *gin.Context) (*datastore.Client, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	projectId := os.Getenv(USER_DATASTORE_PROJECT_ID)
	if isDev() {
		emulatorHost := os.Getenv(USER_DATASTORE_EMULATOR_HOST)
		// log.Debugf("project ID: %s", projectId)
		o1 := []option.ClientOption{
			option.WithEndpoint(emulatorHost),
			option.WithoutAuthentication(),
			option.WithGRPCDialOption(grpc.WithInsecure()),
			option.WithGRPCConnectionPool(50),
		}
		return datastore.NewClient(c, projectId, o1...)
	}
	return datastore.NewClient(c, projectId)
}

func Current(c *gin.Context) User {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	u := current(c)
	if u != None {
		return u
	}

	s, found := c.Get(sessions.DefaultKey)
	if !found {
		return None
	}

	session, ok := s.(sessions.Session)
	if !ok {
		return None
	}

	token, ok := SessionTokenFrom(session)
	if !ok {
		log.Warningf("missing token")
		return None
	}

	log.Debugf("token: %#v", token)

	u = New(token.ID)
	dsClient, err := Client(c)
	if err != nil {
		log.Warningf("Client error: %v", err)
		return None
	}

	err = dsClient.Get(c, u.Key, &u)
	if err != nil {
		log.Warningf("ByID err: %s", err)
		return None
	}
	log.Debugf("u: %#v", u)
	withCurrent(c, u)
	return u
}

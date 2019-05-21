package user

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/SlothNinja/log"
	"bitbucket.org/SlothNinja/restful"
	"cloud.google.com/go/datastore"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gofrs/uuid"
)

func init() {
	gob.Register(SessionToken{})
	gob.Register(new(User0))
	gob.Register(new(User1))
	gob.Register(new(User2))
}

const fqdn = "www.slothninja.com"

const (
	GTMonster = "monsterid"
)

var namespaceUUID = uuid.NewV5(uuid.NamespaceDNS, fqdn)

type User struct {
	ctx     context.Context
	isAdmin bool
	kind    string         `gae:"$kind"`
	ID      int64          `gae:"$id"`
	Parent  *datastore.Key `gae:"$parent"`
	Data
}

// type Data struct {
// 	Name               string        `json:"name" form:"name"`
// 	LCName             string        `json:"lcname"`
// 	Email              string        `json:"email" form:"email"`
// 	GoogleID           string        `json:"googleid"`
// 	XMPPNotifications  bool          `json:"xmppnotifications"`
// 	EmailNotifications bool          `json:"emailnotifications" form:"emailNotifications"`
// 	EmailReminders     bool          `json:"emailreminders"`
// 	Joined             time.Time     `json:"joined"`
// 	CreatedAt          restful.CTime `json:"createdat"`
// 	UpdatedAt          restful.UTime `json:"updatedat"`
// }

// const (
// 	kind             = "User"
// 	uidParam         = "uid"
// 	guserKey         = "guser"
// 	currentKey       = "current"
// 	userKey          = "User"
// 	countKey         = "count"
// 	homePath         = "/"
// 	salt             = "slothninja"
// 	usersKey         = "Users"
// 	NotFound   int64 = -1
// )

type Users []*User

type UserName struct {
	GoogleID string
}

var (
	ErrNotFound     = errors.New("User not found.")
	ErrTooManyFound = errors.New("Found too many users.")
)

func (u *User) CTX() context.Context {
	return u.ctx
}

func RootKey() *datastore.Key {
	return datastore.NameKey("Users", "root", nil)
}

// func NewKey(ctx context.Context, id int64) *gae.Key {
// 	return gae.NewKey(ctx, kind, "", id, RootKey(ctx))
// }

func New(ctx context.Context) *User {
	return &User{ctx: ctx, kind: kind}
}

// Generates ID for User from ID obtained from OAuth OpenID Connect
func ID(s string) string {
	return uuid.NewV5(namespaceUUID, s).String()
}

func (u *User) Equal(u2 *User) bool {
	return u != nil && u2 != nil && u.ID == u2.ID
}

// type Userer interface {
// 	GetUID() string
// 	GetID() int64
// 	GetSID() string
// 	GetData() Data
// 	Gravatar(...string) template.URL
// 	CTX() *gin.Context
// 	IsAdminOrCurrent(*gin.Context) bool
// }

type User0 struct {
	Key *datastore.Key `datastore:"__key__"`
	Data
}

// Implement Userer interface, but use default GetName provided by embedded Data

// // GetUID returns unique openID based string ID
// func (u *User0) GetUID() string {
// 	return ""
// }
//
// // GetID returns id of user.
// func (u *User0) GetID() int64 {
// 	return u.ID
// }
//
// // GetSID returns sid of user.
// func (u *User0) GetSID() string {
// 	return GenID(u.GoogleID)
// }

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

// GetName returns namd and provides default GetName for Userer interface.
func (d Data) GetData() Data {
	return d
}

const (
	kind             = "User"
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

// type Users []*User0

// type UserName struct {
// 	GoogleID string
// }

// var (
// 	ErrNotFound     = errors.New("User not found.")
// 	ErrTooManyFound = errors.New("Found too many users.")
// )

// func (u *User0) CTX() *gin.Context {
// 	return u.c
// }

func rootKey() *datastore.Key {
	return datastore.NameKey("Users2", "root", nil)
}

// func NewKey(c *gin.Context, id int64) *datastore.Key {
// 	return datastore.NewKey(c, kind, "", id, RootKey())
// }

func New0(id int64) *User0 {
	return &User0{Key: datastore.IDKey(kind, id, RootKey())}
}

type User1 struct {
	Key   *datastore.Key `datastore:"__key__"`
	OldID int64          `json:"oldid"`
	Data
}

// func (u *User1) CTX() *gin.Context {
// 	return u.c
// }
//
// // GetUID returns unique openID based string ID
// func (u *User1) GetUID() string {
// 	return ""
// }
//
// // GetID returns id of user.
// func (u *User1) GetID() int64 {
// 	return u.OldID
// }
//
// // GetSID returns sid of user.
// func (u *User1) GetSID() string {
// 	return u.ID
// }

func New1(id string) *User1 {
	return &User1{Key: datastore.NameKey(kind, id, RootKey())}
}

// func (u *User1) Key() *datastore.Key {
// 	return datastore.NameKey(u.Kind, u.ID, u.Parent)
// }

func ToNUser(u *User0) (nu *User1) {
	nu = New1(GenID(u.GoogleID))
	nu.OldID = u.Key.ID
	nu.Data = u.Data
	return
}

func GenID(gid string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(salt+gid)))
}

// func NewKeyFor(c *gin.Context, id int64) *datastore.Key {
// 	u := New0(c)
// 	u.ID = id
// 	return datastore.KeyForObj(c, u)
// }

// func FromGUser(c *gin.Context, gu *user.User) *User0 {
// 	if gu == nil {
// 		return nil
// 	} else {
// 		n := strings.Split(gu.Email, "@")[0]
// 		u := New0(c)
// 		u.Name = n
// 		u.LCName = strings.ToLower(n)
// 		u.Email = gu.Email
// 		u.GoogleID = gu.ID
// 		return u
// 	}
// }

//func ByGoogleID(c *gin.Context, gid string) (*User0, error) {
//	q := datastore.NewQuery(kind).Ancestor(RootKey(c)).Eq("GoogleID", gid).KeysOnly(true)
//
//	var keys []*datastore.Key
//	err := datastore.GetAll(c, q, &keys)
//	if err != nil {
//		return nil, err
//	}
//
//	u := New0(c)
//	//var key *datastore.Key
//	switch l := len(keys); l {
//	case 0:
//		return nil, ErrNotFound
//	case 1:
//		datastore.PopulateKey(u, keys[0])
//		if err = datastore.Get(c, u); err != nil {
//			return nil, err
//		}
//	default:
//		return nil, ErrTooManyFound
//	}
//
//	return u, nil
//}

func ByGoogleID(c *gin.Context, gid string) (*User1, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	client, err := Client(c)
	if err != nil {
		return nil, err
	}

	u := New0(0)
	u.GoogleID = gid
	nu := ToNUser(u)
	if err = client.Get(c, nu.Key, nu); err != nil {
		if err == datastore.ErrNoSuchEntity {
			err = ErrNotFound
		}
		log.Warningf(err.Error())
		return nil, err
	}

	return nu, nil
}

//func GetMulti(c *gin.Context, ks []*datastore.Key) (Users, error) {
//	us := make([]*User0, len(ks))
//	for i, k := range ks {
//		us[i] = new(User0)
//		datastore.PopulateKey(us[i], k)
//	}
//	err := datastore.Get(c, us)
//	return us, err
//}
//
//func ByID(c *gin.Context, id int64) (u *User0, err error) {
//	u = New0(c)
//	u.ID = id
//	err = datastore.Get(c, u)
//	return
//}
//
//func BySID(c *gin.Context, sid string) (*User0, error) {
//	id, err := strconv.ParseInt(sid, 10, 64)
//	if err != nil {
//		return nil, err
//	}
//	return ByID(c, id)
//}
//
//func ByIDS(c *gin.Context, ids []int64) (Users, error) {
//	ks := make([]*datastore.Key, len(ids))
//	for i, id := range ids {
//		ks[i] = NewKey(c, id)
//	}
//	return GetMulti(c, ks)
//}

func AllQuery(c *gin.Context) *datastore.Query {
	restful.ContextFrom(c)
	return datastore.NewQuery(kind).Ancestor(RootKey())
}

func AllQuery2(c *gin.Context) *datastore.Query {
	return datastore.NewQuery(kind).Ancestor(rootKey())
}

func ByOldEntries(c *gin.Context, email string) (id0 int64, id1 string, gid string, joinedAt time.Time, found bool, err error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	log.Debugf("email: %s", email)

	client, err := Client(c)
	if err != nil {
		return id0, id1, gid, joinedAt, found, err
	}

	q := datastore.NewQuery(kind).Ancestor(RootKey()).Filter("Email =", email).KeysOnly()

	ks, err := client.GetAll(c, q, nil)
	if err != nil && err != datastore.ErrNoSuchEntity {
		return id0, id1, gid, joinedAt, found, err
	}
	log.Debugf("ks: %#v", ks)

	if len(ks) == 0 {
		return id0, id1, gid, joinedAt, found, nil
	}

	for _, k := range ks {
		switch {
		case k.ID != 0:
			found = true
			id0 = k.ID
			u0 := New0(0)
			if gid == "" {
				err := client.Get(c, k, u0)
				if err != nil {
					return id0, id1, gid, joinedAt, found, err
				}
				gid = u0.GoogleID
				if joinedAt.IsZero() {
					joinedAt = u0.CreatedAt
				}
			}
		case k.Name != "":
			found = true
			id1 = k.Name
			u1 := New1("")
			if gid == "" {
				err := client.Get(c, k, u1)
				if err != nil {
					return id0, id1, gid, joinedAt, found, err
				}
				gid = u1.GoogleID
				joinedAt = u1.JoinedAt
			}
		}
	}
	return id0, id1, gid, joinedAt, found, nil
}

func addUnique(ks []*datastore.Key, k *datastore.Key) []*datastore.Key {
	for i := range ks {
		if ks[i].Equal(k) {
			return ks
		}
	}
	return append(ks, k)
}

//func getByGoogleID(c *gin.Context, gid string) (*User0, error) {
//	itm := memcache.NewItem(c, MCKey(c, gid))
//	if err := memcache.Get(c, itm); err != nil {
//		return nil, err
//	}
//
//	u := New0(c)
//	if err := decode(u, itm.Value()); err != nil {
//		return nil, err
//	}
//	return u, nil
//}

//func (u User0) encode() ([]byte, error) {
//	return codec.Encode(u)
//}
//
//func decode(dst *User0, v []byte) error {
//	return codec.Decode(dst, v)
//}
//
// func MCKey(c *gin.Context, gid string) string {
// 	return info.VersionID(c) + gid
// }

//func setByGoogleID(c *gin.Context, gid string, u *User0) error {
//	if v, err := u.encode(); err != nil {
//		return err
//	} else {
//		return memcache.Set(c, memcache.NewItem(c, MCKey(c, gid)).SetValue(v))
//	}
//}

// func IsAdmin(c *gin.Context) bool {
// 	return user.IsAdmin(c)
// }

func IsAdmin(c *gin.Context) bool {
	cu := CurrentFrom(c)
	return cu.Admin
}

// func (u *User0) IsAdmin() bool {
// 	return u != nil && u.isAdmin
// }

// func (u *User0) IsAdminOrCurrent(c *gin.Context) bool {
// 	return IsAdmin(u) || u.IsCurrent(c)
// }

func (u *User) IsAdminOrCurrent(c *gin.Context) bool {
	return (u != nil && u.Admin) || u.IsCurrent(c)
}

func (u *User) Gravatar(options ...string) template.URL {
	return template.URL(GravatarURL(u.Email, options...))
}

func (u *User0) Gravatar(options ...string) template.URL {
	return template.URL(GravatarURL(u.Email, options...))
}

func (u *User1) Gravatar(options ...string) template.URL {
	return template.URL(GravatarURL(u.Email, options...))
}

func (u *User2) Gravatar(options ...string) template.URL {
	return template.URL(GravatarURL(u.Email, options...))
}

func GravatarURL(email string, options ...string) string {
	size := "80"
	if len(options) == 1 {
		size = options[0]
	}

	hash, _ := emailHash(email)
	return fmt.Sprintf("http://www.gravatar.com/avatar/%s?s=%s&d=monsterid", hash, size)
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

func (u *User2) Update(c *gin.Context, cu *User2) error {
	n := New2("")
	if err := c.ShouldBindWith(n, binding.FormPost); err != nil {
		return err
	}

	if u.Admin {
		if n.Email != "" {
			u.Email = n.Email
		}
	}

	if u.Admin || u.ID() == cu.ID() {
		if err := u.updateName(c, n.Name); err != nil {
			return err
		}
		u.EmailNotifications = n.EmailNotifications
	}

	return nil
}

func (u *User2) updateName(c *gin.Context, n string) error {
	matcher := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._%+\-]+$`)

	switch {
	case n == u.Name:
		return nil
	case len(n) > 15:
		return fmt.Errorf("%q is too long.", n)
	case !matcher.MatchString(n):
		return fmt.Errorf("%q is not a valid user name.", n)
	case !NameIsUnique(c, n):
		return fmt.Errorf("%q is not a unique user name.", n)
	}

	u.Name = n
	u.LCName = strings.ToLower(n)
	return nil
}

func NameIsUnique(c *gin.Context, name string) bool {
	client, err := Client(c)
	if err != nil {
		return false
	}

	LCName := strings.ToLower(name)

	q := datastore.NewQuery("User").Filter("LCName =", LCName)
	if cnt, err := client.Count(c, q); err != nil {
		return false
	} else {
		return cnt == 0
	}
}

// func (u *User0) Equal(u2 *User0) bool {
// 	return u2 != nil && u != nil && u.ID == u2.ID
// }

func Equal(u1, u2 *User) bool {
	return u1 != nil && u2 != nil && u1.ID == u2.ID
}

//func (u *User0) Link() template.HTML {
//	if u == nil {
//		return ""
//	}
//	return LinkFor(u.Key.ID, u.Name)
//}

func LinkFor(uid, name string) template.HTML {
	return template.HTML(fmt.Sprintf("<a href=%q>%s</a>", PathFor(uid), name))
}

func PathFor(uid string) template.HTML {
	return template.HTML("/user/show/" + uid)
}

// func LinkFor2(uid, name string) template.HTML {
// 	return template.HTML(fmt.Sprintf("<a href=%q>%s</a>", PathFor2(uid), name))
// }
//
// func PathFor2(uid string) template.HTML {
// 	return template.HTML("/user/show/" + uid)
// }

// func GetGUserHandler(c *gin.Context) {
// 	log.Debug("Entering")
// 	defer log.Debug("Exiting")
//
// 	WithGUser(c, user.Current(c))
// }

// // Use after GetGUserHandler handler
// func GetCUserHandler(c *gin.Context) {
// 	log.Debug("Entering")
// 	defer log.Debug("Exiting")
//
// 	var u *User0
// 	if gu := GUserFrom(c); gu != nil {
// 		// Attempt to fetch and return stored User
// 		if nu, err := ByGoogleID(c, gu.ID); err != nil {
// 			log.Debug(err.Error())
// 		} else {
// 			u = New0(c)
// 			u.ID, u.Data, u.isAdmin = nu.OldID, nu.Data, user.IsAdmin(c)
// 		}
// 	}
// 	WithCurrent(c, u)
// }
//
// // Use after GetGUserHandler and GetUserHandler handlers
// func RequireLogin() gin.HandlerFunc {
// 	return func(c *gin.Context) {
//
// 		if gu := GUserFrom(c); gu == nil {
// 			log.Warning("RequireLogin failed.")
// 			c.Redirect(http.StatusSeeOther, "/")
// 			c.Abort()
// 		}
// 	}
// }

// func RequireCurrentUser() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		log.Debugf("Entering")
// 		defer log.Debugf("Exiting")
//
// 		cu := CurrentFrom(c)
// 		if cu != nil {
// 			return
// 		}
// 		log.Warningf("RequireCurrentUser failed.")
// 		c.Redirect(http.StatusSeeOther, "/")
// 		c.Abort()
// 	}
// }

func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debugf("Entering")
		defer log.Debugf("Exiting")

		cu := CurrentFrom(c)
		if cu != nil && cu.Admin {
			return
		}
		log.Warningf("user not admin.")
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
	}
}

func Fetch(c *gin.Context) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	client, err := Client(c)
	if err != nil {
		log.Errorf(err.Error())
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
	}

	uid := getUID(c)
	u := New2(uid)
	if err := client.Get(c, u.Key, u); err != nil {
		log.Errorf("Unable to get user for id: %v", c.Param("uid"))
		c.Redirect(http.StatusSeeOther, "/")
		c.Abort()
	} else {
		WithUser(c, u)
	}
}

func FetchAll(c *gin.Context) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	us, cnt, err := getFiltered2(c, c.PostForm("start"), c.PostForm("length"))

	if err != nil {
		log.Errorf(err.Error())
		c.Redirect(http.StatusSeeOther, homePath)
		c.Abort()
	}
	withUsers(withCount(c, cnt), us)
}

func getFiltered(c *gin.Context, start, length string) ([]interface{}, int, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	client, err := Client(c)
	if err != nil {
		return nil, 0, err
	}

	q := AllQuery(c).Order("GoogleID").KeysOnly()

	cnt, err := client.Count(c, q)
	if err != nil {
		return nil, 0, err
	}

	if start != "" {
		if st, err := strconv.ParseInt(start, 10, 32); err == nil {
			q = q.Offset(int(st))
		}
	}

	if length != "" {
		if l, err := strconv.ParseInt(length, 10, 32); err == nil {
			q = q.Limit(int(l))
		}
	}

	ks, err := client.GetAll(c, q, nil)
	if err != nil {
		return nil, 0, err
	}

	l := len(ks)
	us := make([]interface{}, l)
	for i := range us {
		if id := ks[i].ID; id != 0 {
			u := New0(0)
			us[i] = u
		} else {
			u := New1("")
			us[i] = u
		}
	}

	err = client.GetMulti(c, ks, us)
	if err != nil {
		return nil, 0, err
	}
	return us, cnt, nil
}

func getFiltered2(c *gin.Context, start, length string) ([]*User2, int, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	client, err := Client(c)
	if err != nil {
		return nil, 0, err
	}

	q := AllQuery2(c).Order("GoogleID").KeysOnly()

	cnt, err := client.Count(c, q)
	if err != nil {
		return nil, 0, err
	}

	if start != "" {
		if st, err := strconv.ParseInt(start, 10, 32); err == nil {
			q = q.Offset(int(st))
		}
	}

	if length != "" {
		if l, err := strconv.ParseInt(length, 10, 32); err == nil {
			q = q.Limit(int(l))
		}
	}

	ks, err := client.GetAll(c, q, nil)
	if err != nil {
		return nil, 0, err
	}

	l := len(ks)
	us := make([]*User2, l)
	err = client.GetMulti(c, ks, us)
	if err != nil {
		return nil, 0, err
	}
	return us, cnt, nil
}

//func FetchAll(c *gin.Context) {
//	log.Debug("Entering user#Fetch")
//	defer log.Debug("Exiting user#Fetch")
//
//	var (
//		ks  []*datastore.Key
//		err error
//	)
//
//	if err = datastore.GetAll(c, q, &ks); err != nil {
//		log.Error("unable to get users, error %v", err.Error())
//		c.Redirect(http.StatusSeeOther, "/")
//		c.Abort()
//	}
//
//	u := New0(c)
//	u.ID = uid
//	if err = datastore.Get(c, u); err != nil {
//		log.Error("Unable to get user for id: %v", c.Param("uid"))
//		c.Redirect(http.StatusSeeOther, "/")
//		c.Abort()
//	} else {
//		WithUser(c, u)
//	}
//}

// func getUID(c *gin.Context) (id int64, err error) {
// 	if id, err = strconv.ParseInt(c.Param(uidParam), 10, 64); err != nil {
// 		id = NotFound
// 	}
// 	return
// }

func getUID(c *gin.Context) string {
	return c.Param(uidParam)
}

func Fetched(c *gin.Context) *User {
	return From(c)
}

func Gravatar(u *User) template.HTML {
	return template.HTML(fmt.Sprintf(`<a href="/user/show/%d"><img src=%q alt="Gravatar" class="black-border" /></a>`, u.ID, u.Gravatar()))
}

func Gravatar2(u *User2) template.HTML {
	return template.HTML(fmt.Sprintf(`<a href="/user/show/%s"><img src=%q alt="Gravatar" class="black-border" /></a>`, u.ID(), u.Gravatar()))
}

func NGravatar(nu *User1) template.HTML {
	return template.HTML(fmt.Sprintf(`<a href="/user/show/%s"><img src=%q alt="Gravatar" class="black-border" /></a>`, nu.Key.Name, nu.Gravatar()))
}

func from(c *gin.Context, key string) *User {
	u2 := from2(c, key)
	if u2 == nil {
		return nil
	}
	return u2.ToUser(c)
}

func From(c *gin.Context) *User {
	return from(c, userKey)
}

func CurrentFrom(c *gin.Context) *User {
	return from(c, currentKey)
}

func from2(c *gin.Context, key string) *User2 {
	u, ok := c.Value(key).(*User2)
	if !ok {
		return nil
	}
	return u
}

func From2(c *gin.Context) *User2 {
	return from2(c, userKey)
}

func CurrentFrom2(c *gin.Context) *User2 {
	return from2(c, currentKey)
}

// func (u *User0) IsCurrent(c *gin.Context) bool {
// 	cu := CurrentFrom(c)
// 	return u != nil && cu != nil && Equal(u, cu)
// }

func (u *User) IsCurrent(c *gin.Context) bool {
	cu := CurrentFrom(c)
	return u != nil && cu != nil && Equal(u, cu)
}

// func GUserFrom(c *gin.Context) (u *user.User) {
// 	log.Debug("Entering")
// 	defer log.Debug("Exiting")
//
// 	u, _ = c.Value(guserKey).(*user.User)
// 	log.Debug("u: %#v", u)
// 	return
// }

func WithUser(c *gin.Context, u *User2) {
	c.Set(userKey, u)
}

// func WithGUser(c *gin.Context, u *user.User) {
// 	c.Set(guserKey, u)
// }

func WithCurrent(c *gin.Context, u *User2) {
	c.Set(currentKey, u)
}

func UsersFrom(c *gin.Context) []*User2 {
	us, ok := c.Value(usersKey).([]*User2)
	if !ok {
		return nil
	}
	return us
}

func withUsers(c *gin.Context, us []*User2) {
	c.Set(usersKey, us)
}

func withCount(c *gin.Context, cnt int) *gin.Context {
	c.Set(countKey, cnt)
	return c
}

func CountFrom(c *gin.Context) int {
	cnt, _ := c.Value(countKey).(int)
	return cnt
}

type User2 struct {
	Key     *datastore.Key `datastore:"__key__" json:"-"`
	User0ID int64          `json:"user0id"`
	User1ID string         `json:"user1id"`
	Data
}

func (u *User2) ID() string {
	if u == nil || u.Key == nil {
		return ""
	}
	return u.Key.Name
}

func (u *User2) MarshalJSON() ([]byte, error) {
	hash, err := emailHash(u.Email)
	if err != nil {
		return nil, err
	}

	type u2 User2
	return json.Marshal(struct {
		ID        string `json:"id"`
		EmailHash string `json:"emailHash"`
		u2
	}{
		ID:        u.ID(),
		EmailHash: hash,
		u2:        u2(*u),
	})
}

// // GetUID returns unique openID based string ID
// func (u *User2) GetUID() string {
// 	return u.ID
// }
//
// // GetID returns id of user.
// func (u *User2) GetID() int64 {
// 	return u.User0ID
// }
//
// // GetSID returns sid of user.
// func (u *User2) GetSID() string {
// 	return u.User1ID
// }
//
// func (u *User2) Key() *datastore.Key {
// 	return datastore.NameKey(u.Kind, u.ID, u.Parent)
// }

func New2(id string) *User2 {
	return &User2{Key: newKey2(id)}
}

func newKey2(id string) *datastore.Key {
	return datastore.NameKey(kind, id, rootKey())
}

// func (u *User2) CTX() *gin.Context {
// 	return u.c
// }
//
func (u2 *User2) ToUser(c *gin.Context) *User {
	u0 := New(c)
	u0.ID = u2.User0ID
	u0.Data = u2.Data
	return u0
}

// func (u2 *User2) ToUser1(c *gin.Context) *User1 {
// 	u1 := New1(c)
// 	u1.ID = u2.User1ID
// 	u1.Parent = u2.Parent
// 	u1.Kind = u2.Kind
// 	u1.Data = u2.Data
// 	u1.OldID = u2.User0ID
// 	return u1
// }

// func FromSession(c *gin.Context, s sessions.Session) *User2 {
// 	uinfo, ok := InfoFrom(s)
// 	if !ok {
// 		return nil
// 	}
//
// 	log.Debug("uinfo: %#v", uinfo)
//
// 	u := New2(c)
// 	u.Name = Name(uinfo.Email)
// 	u.LCName = LCName(uinfo.Email)
// 	u.Email = uinfo.Email
// 	u.GoogleID = uinfo.ID
// 	u.Admin = uinfo.Admin
// 	return u
// }

func InfoFrom(s sessions.Session) (Info, bool) {
	uinfo, ok := s.Get(uinfoKey).(Info)
	return uinfo, ok
}

func Name(email string) string {
	return strings.Split(email, "@")[0]
}

func LCName(email string) string {
	return strings.ToLower(Name(email))
}

type SessionToken struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (u *User2) To(s sessions.Session) error {
	s.Set(sessionKey, SessionToken{ID: u.ID(), Email: u.Email})
	return s.Save()
}

func SessionTokenFrom(s sessions.Session) (SessionToken, bool) {
	token, ok := s.Get(sessionKey).(SessionToken)
	return token, ok
}

// func (uinfo Info) To(s sessions.Session) error {
// 	info := Info{
// 		ID:     ID(uinfo.Sub),
// 		LCName: LCName(uinfo.Email),
// 	}
// 	s.Set(uinfoKey, uinfo)
// 	return s.Save()
// }

func ByID(c *gin.Context, id string) (*User2, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	client, err := Client(c)
	if err != nil {
		return nil, err
	}

	u := New2(id)
	log.Debugf("key: %v", u.Key)
	err = client.Get(c, u.Key, u)
	return u, err
}

func ByLCName(c *gin.Context, lcname string) (*User2, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	client, err := Client(c)
	if err != nil {
		return nil, err
	}

	var us []*User2
	ks, err := client.GetAll(c, datastore.NewQuery(kind).Filter("LCName =", lcname), &us)
	if err != nil {
		return nil, err
	}
	switch l := len(ks); l {
	case 0:
		return nil, nil
	case 1:
		return us[0], nil
	default:
		return nil, fmt.Errorf("too many users returned")
	}
}

func ByParam(c *gin.Context, param string) (*User2, error) {
	return ByID(c, c.Param(param))
}

func ByKeys(c *gin.Context, ks []*datastore.Key) ([]*User2, error) {
	client, err := Client(c)
	if err != nil {
		return nil, err
	}

	us := make([]*User2, len(ks))
	for i := range us {
		us[i] = New2("")
	}

	err = client.GetMulti(c, ks, us)
	if err != nil {
		return nil, err
	}
	return us, nil
}

func Client(c *gin.Context) (*datastore.Client, error) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")
	// projectId := os.Getenv("DATASTORE_PROJECT_ID")
	// emulatorHost := "user.slothninja.com:8081"
	// log.Debugf("project ID: %s", projectId)
	// o1 := []option.ClientOption{
	// 	option.WithEndpoint(emulatorHost),
	// 	option.WithoutAuthentication(),
	// 	option.WithGRPCDialOption(grpc.WithInsecure()),
	// 	option.WithGRPCConnectionPool(50),
	// }
	// return datastore.NewClient(c, projectId, o1...)
	return datastore.NewClient(c, "")
}

func GetCUserHandler2(c *gin.Context) {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	session := sessions.Default(c)
	token, ok := SessionTokenFrom(session)
	if !ok {
		log.Warningf("missing token")
		return
	}

	u, err := ByID(c, token.ID)
	if err != nil {
		log.Warningf("ByID err: %s", err)
		return
	}
	WithCurrent(c, u)
}

func Current(c *gin.Context) *User2 {
	log.Debugf("Entering")
	defer log.Debugf("Exiting")

	u := CurrentFrom2(c)
	if u != nil {
		return u
	}

	session := sessions.Default(c)
	token, ok := SessionTokenFrom(session)
	if !ok {
		log.Warningf("missing token")
		return nil
	}

	log.Debugf("token: %#v", token)

	u, err := ByID(c, token.ID)
	if err != nil {
		log.Warningf("ByID err: %s", err)
		return nil
	}
	WithCurrent(c, u)
	return u
}

// Use after GetUser2Handler handler
// func RequireLogin(c *gin.Context) {
// 	cu := Current(c)
// 	if cu != nil {
// 		return
// 	}
// 	log.Warningf("RequireLogin failed.")
// 	c.Redirect(http.StatusSeeOther, "/")
// 	c.Abort()
// }

func (u *User) Link() template.HTML {
	if u == nil {
		return ""
	}
	return template.HTML(u.Name)
}

func (u *User2) Link() template.HTML {
	if u == nil {
		return ""
	}
	return linkFor(u.ID(), u.Name)
}

func linkFor(uid string, name string) template.HTML {
	return template.HTML(fmt.Sprintf("<a href=%q>%s</a>", pathFor(uid), name))
}

func pathFor(uid string) string {
	return "/user/show/" + uid
}

// Declare a struct capable of handling any type of entity.
// It implements the PropertyLoadSaver interface
type arbitraryEntity struct {
	properties []datastore.Property
}

func (e *arbitraryEntity) Load(ps []datastore.Property) error {
	e.properties = ps
	return nil
}

func (e *arbitraryEntity) Save() ([]datastore.Property, error) {
	return e.properties, nil
}

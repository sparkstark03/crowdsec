package middlewares

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
)

var identityKey = "id"

// User demo
type User struct {
	UserName  string
	FirstName string
	LastName  string
}

type JWT struct {
	Middleware *jwt.GinJWTMiddleware
	DbClient   *database.Client
}

func PayloadFunc(data interface{}) jwt.MapClaims {
	if value, ok := data.(*models.WatcherAuthRequest); ok {
		return jwt.MapClaims{
			identityKey: value.MachineID,
		}
	}
	return jwt.MapClaims{}
}

func IdentityHandler(c *gin.Context) interface{} {
	claims := jwt.ExtractClaims(c)
	return &models.WatcherAuthRequest{
		MachineID: claims[identityKey].(string),
	}
}

func (j *JWT) Authenticator(c *gin.Context) (interface{}, error) {
	var loginInput models.WatcherAuthRequest
	if err := c.ShouldBind(&loginInput); err != nil {
		return "", jwt.ErrMissingLoginValues
	}
	machineID := loginInput.MachineID
	password := loginInput.Password

	HashedPassword := sha256.New()
	HashedPassword.Write([]byte(password))
	hashPassword := fmt.Sprintf("%x", HashedPassword.Sum(nil))

	exist, err := j.DbClient.Ent.Machine.Query().Where(machine.MachineId(machineID)).Where(machine.Password(hashPassword)).Select(machine.FieldID).Strings(j.DbClient.CTX)
	if err != nil {
		return nil, jwt.ErrFailedAuthentication
	}

	if len(exist) == 0 {
		return nil, jwt.ErrFailedAuthentication
	}

	// here implem when is validated machine logic, for now just login with admin/admin or test/test
	return &models.WatcherAuthRequest{
		MachineID: machineID,
		Scenarios: []string{"crowdsecurity/test"},
	}, nil

}

func Authorizator(data interface{}, c *gin.Context) bool {
	return true
}

func Unauthorized(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{
		"code":    code,
		"message": message,
	})
}

func NewJWT(dbClient *database.Client) (*JWT, error) {
	secret := os.Getenv("SECRET")
	if secret == "" {
		secret = "crowdsecret"
	}
	jwtMiddleware := &JWT{
		DbClient: dbClient,
	}

	ret, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:           "Crowdsec API local",
		Key:             []byte(secret),
		Timeout:         time.Hour,
		MaxRefresh:      time.Hour,
		IdentityKey:     "id",
		PayloadFunc:     PayloadFunc,
		IdentityHandler: IdentityHandler,
		Authenticator:   jwtMiddleware.Authenticator,
		Authorizator:    Authorizator,
		Unauthorized:    Unauthorized,
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",
		TimeFunc:        time.Now,
	})

	errInit := ret.MiddlewareInit()
	if errInit != nil {
		return &JWT{}, fmt.Errorf("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	if err != nil {
		return &JWT{}, err
	}

	return &JWT{Middleware: ret}, nil
}

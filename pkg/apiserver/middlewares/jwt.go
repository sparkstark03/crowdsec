package middlewares

import (
	jwt "github.com/appleboy/gin-jwt/v2"
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

func Authenticator(c *gin.Context) (interface{}, error) {
	var loginInput models.WatcherAuthRequest
	if err := c.ShouldBind(&loginInput); err != nil {
		return "", jwt.ErrMissingLoginValues
	}
	machineId := loginInput.MachineID
	password := loginInput.Password
	// here implem when is validated machine logic, for now just login with admin/admin or test/test
	if (machineId == "admin" && password == "admin") || (machineId == "test" && password == "test") {
		return &models.WatcherAuthRequest{
			MachineID: machineId,
			Scenarios: []string{"crowdsecurity/test"},
		}, nil
	}

	return nil, jwt.ErrFailedAuthentication
}

func Authorizator(data interface{}, c *gin.Context) bool {
	if value, ok := data.(*models.WatcherAuthRequest); ok && value.MachineID == "admin" {
		return true
	}

	return false
}

func Unauthorized(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{
		"code":    code,
		"message": message,
	})
}

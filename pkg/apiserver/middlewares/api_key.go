package middlewares

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/blocker"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var (
	APIKeyHeader = "X-Api-Key"
)

type APIKey struct {
	HeaderName string
}

func GenerateKey(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func NewAPIKey() *APIKey {
	return &APIKey{
		HeaderName: APIKeyHeader,
	}
}

func (a *APIKey) MiddlewareFunc(controller *controllers.Controller) gin.HandlerFunc {
	return func(c *gin.Context) {
		val, ok := c.Request.Header[APIKeyHeader]
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "access forbidden"})
			c.Abort()
			return
		}

		hashKey, err := bcrypt.GenerateFromPassword([]byte(val[0]), bcrypt.DefaultCost)
		if err != nil {
			log.Errorf("failed hashing apiKey %v: %v", val[0], err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			c.Abort()
			return
		}
		log.Printf("key : %v", val[0])
		log.Printf("hashed key : %v", string(hashKey))
		exist, err := controller.DBClient.Ent.Blocker.Query().
			Where(blocker.APIKeyEQ(string(hashKey))).
			Select(blocker.FieldAPIKey).
			Strings(controller.DBClient.CTX)
		if err != nil {
			log.Errorf("unable to get current api key: %s", err)
			c.Abort()
			return
		}

		if len(exist) == 0 {
			c.JSON(http.StatusForbidden, gin.H{"error": "access forbidden"})
			c.Abort()
			return
		}
		c.Next()
	}
}

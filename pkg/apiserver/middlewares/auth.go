package middlewares

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/blocker"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

var (
	apiKeyHeaderName = "X-Api-Key"
)

func generateKey(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func apiKeyRequired(controller *controllers.Controller) gin.HandlerFunc {
	return func(c *gin.Context) {
		val, ok := c.Request.Header[apiKeyHeaderName]
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "access forbidden"})
			c.Abort()
			return
		}

		hashedKey := sha256.New()
		hashedKey.Write([]byte(val[0]))

		hashStr := fmt.Sprintf("%x", hashedKey.Sum(nil))
		exist, err := controller.Client.Blocker.Query().Where(blocker.APIKeyEQ(hashStr)).Select(blocker.FieldAPIKey).Strings(controller.Ectx)
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

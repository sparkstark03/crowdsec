package apiserver

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares"

	"github.com/crowdsecurity/crowdsec/pkg/apiserver/controllers"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

var (
	keyLength        = 32
	apiKeyHeaderName = "X-Api-Key"
)

type APIServer struct {
	url      string
	certPath string
	dbClient *ent.Client
	logFile  string
	ctx      context.Context
}

func NewServer(config *csconfig.CrowdSec) (*APIServer, error) {
	dbClient, err := database.NewClient(config.DBConfig)
	if err != nil {
		return &APIServer{}, fmt.Errorf("unable to init database client: %s", config.DBConfig.Path)
	}

	return &APIServer{
		url:      config.APIServerConfig.URL,
		certPath: config.APIServerConfig.CertPath,
		logFile:  config.APIServerConfig.LogFile,
		dbClient: dbClient,
		ctx:      context.Background(),
	}, nil

}

func (s *APIServer) Run() {
	controller := controllers.Controller{
		Ectx:   s.ctx,
		Client: s.dbClient,
	}
	defer controller.Client.Close()
	file, err := os.Create(s.logFile)
	if err != nil {
		log.Fatalf(err.Error())
	}
	gin.DefaultWriter = io.MultiWriter(file, os.Stdout)

	router := gin.New()

	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))

	router.Use(gin.Recovery())

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"data": "hello world"})
	})
	router.POST("/machines", controller.CreateMachine)
	router.POST("/alerts", controller.CreateAlert)
	router.GET("/alerts", controller.FindAlerts)
	router.DELETE("/alerts", controller.DeleteAlerts)

	apiKeyAuth := router.Group("/")
	apiKeyAuth.Use(middlewares.APIKeyRequired(&controller))
	{
		apiKeyAuth.GET("/decisions", controller.GetDecision)
	}

	router.Run(s.url)
}

func (s *APIServer) Generate(name string) (string, error) {
	key, err := middlewares.GenerateKey(keyLength)
	if err != nil {
		return "", fmt.Errorf("unable to generate api key: %s", err)
	}

	hashedKey := sha256.New()
	hashedKey.Write([]byte(key))

	_, err = s.dbClient.Blocker.
		Create().
		SetName(name).
		SetAPIKey(fmt.Sprintf("%x", hashedKey.Sum(nil))).
		SetRevoked(false).
		Save(s.ctx)
	if err != nil {
		return "", fmt.Errorf("unable to save api key in database: %s", err)
	}
	return key, nil
}

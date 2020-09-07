package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/crowdsecurity/crowdsec/cmd/api/controllers"
	"github.com/crowdsecurity/crowdsec/cmd/api/ent"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

var (
	keyLength        = 32
	apiKeyHeaderName = "X-Api-Key"
)

type APIConfig struct {
	URL      string `yaml:"url"`
	CertPath string `yaml:"cert_path"`
	LogFile  string `yaml:"log_file"`
}

type API struct {
	url      string
	certPath string
	dbClient *ent.Client
	logFile  string
	ctx      context.Context
}

func newAPI(config *Config) (*API, error) {
	dbClient, err := newDatabaseClient(config.DB)
	if err != nil {
		return &API{}, fmt.Errorf("unable to init database client: %s", config.DB.Path)
	}

	return &API{
		url:      config.API.URL,
		certPath: config.API.CertPath,
		logFile:  config.API.LogFile,
		dbClient: dbClient,
		ctx:      context.Background(),
	}, nil

}

func (a *API) Run() {
	controller := controllers.Controller{
		Ectx:   a.ctx,
		Client: a.dbClient,
	}
	defer controller.Client.Close()

	file, err := os.Create(a.logFile)
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
	apiKeyAuth.Use(apiKeyRequired(&controller))
	{
		apiKeyAuth.GET("/decisions", controller.GetDecision)
	}

	router.Run(a.url)
}

func (a *API) Generate(name string) (string, error) {
	key, err := generateKey(keyLength)
	if err != nil {
		return "", fmt.Errorf("unable to generate api key: %s", err)
	}

	hashedKey := sha256.New()
	hashedKey.Write([]byte(key))

	_, err = a.dbClient.Blocker.
		Create().
		SetName(name).
		SetAPIKey(fmt.Sprintf("%x", hashedKey.Sum(nil))).
		SetRevoked(false).
		Save(a.ctx)
	if err != nil {
		return "", fmt.Errorf("unable to save api key in database: %s", err)
	}
	return key, nil
}

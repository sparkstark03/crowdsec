package main

import (
	"context"
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
}

func newAPI(config *Config) (*API, error) {
	dbClient, err := newDatabaseClient(config.DB)
	if err != nil {
		return &API{}, fmt.Errorf("unable to init database client: %s")
	}

	return &API{
		url:      config.API.URL,
		certPath: config.API.CertPath,
		logFile:  config.API.LogFile,
		dbClient: dbClient,
	}, nil

}

func (a *API) Run() {
	controller := controllers.Controller{
		Ectx:   context.Background(),
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
	router.GET("/decisions/ip/:ipText", controller.FindDecisionByIp)

	router.Run(a.url)
}

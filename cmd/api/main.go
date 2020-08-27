package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/crowdsecurity/crowdsec/cmd/api/controllers"
	"github.com/crowdsecurity/crowdsec/cmd/api/ent"

	_ "github.com/mattn/go-sqlite3"
)

func ConnectDatabase() *ent.Client {
	client, err := ent.Open("sqlite3", "file:ent.db?_fk=1")
	if err != nil {
		log.Fatalf("failed opening connection to sqlite: %v", err)
	}

	if err = client.Schema.Create(context.Background()); err != nil {
		log.Fatalf("failed creating schema resources: %v", err)
	}
	return client
}

func main() {
	controller := controllers.Controller{
		Ectx:   context.Background(),
		Client: ConnectDatabase(),
	}
	defer controller.Client.Close()

	file, err := os.Create("api.log")
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

	router.Run()
}

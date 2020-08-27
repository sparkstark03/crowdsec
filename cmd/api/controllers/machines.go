package controllers

import (
	"context"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"

	"github.com/crowdsecurity/crowdsec/cmd/api/ent"
)

type CreateMachineInput struct {
	MachineId string `json:"machineId" binding:"required"`
	Password  string `json:"password" binding:"required"`
	IpAddress string `json:"ipAddress" binding:"required"`
	Token     string `json:"token" binding:"required"`
}

type Controller struct {
	Ectx   context.Context
	Client *ent.Client
}

func (c *Controller) CreateMachine(gctx *gin.Context) {
	var input CreateMachineInput
	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	machine, err := c.Client.Machine.
		Create().
		SetMachineId(input.MachineId).
		SetPassword(input.Password).
		SetIpAddress(input.IpAddress).
		SetToken(input.Token).
		Save(c.Ectx)
	if err != nil {
		log.Errorf("failed creating machine: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating machine"})
		return
	}
	gctx.JSON(http.StatusOK, gin.H{"data": machine})
	return
}

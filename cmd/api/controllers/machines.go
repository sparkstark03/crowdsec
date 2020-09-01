package controllers

import (
	"context"
	"fmt"
	"github.com/crowdsecurity/crowdsec/cmd/api/ent"
	"github.com/crowdsecurity/crowdsec/cmd/api/ent/machine"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type CreateMachineInput struct {
	MachineId string `json:"machineId" binding:"required"`
	Password  string `json:"password" binding:"required"`
	IpAddress string `json:"ipAddress" binding:"required"`
}

func QueryMachine(ctx context.Context, client *ent.Client, machineId int) (*ent.Machine, error) {
	machine, err := client.Machine.
		Query().
		Where(machine.IDEQ(machineId)).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed querying user: %v", err)
	}
	return machine, nil
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
		Save(c.Ectx)
	if err != nil {
		log.Errorf("failed creating machine: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating machine"})
		return
	}
	gctx.JSON(http.StatusOK, gin.H{"data": machine})
	return
}

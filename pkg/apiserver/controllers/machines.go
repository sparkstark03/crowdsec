package controllers

import (
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func QueryMachine(ctx context.Context, client *ent.Client, machineId string) (*ent.Machine, error) {
	machine, err := client.Debug().Machine.
		Query().
		Where(machine.MachineIdEQ(machineId)).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed querying user: %v", err)
	}
	return machine, nil
}

func (c *Controller) CreateMachine(gctx *gin.Context) {
	var input models.WatcherRegistrationRequest
	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	machineExist, err := c.DBClient.Ent.Machine.
		Query().
		Where(machine.MachineIdEQ(input.MachineID)).
		Select(machine.FieldMachineId).Strings(c.Ectx)
	if len(machineExist) > 0 {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("user '%s' already exist", input.MachineID)})
		return
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Errorf("failed hashing password %v: %v", input.Password, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating machine"})
		return
	}

	machine, err := c.DBClient.Ent.Machine.
		Create().
		SetMachineId(input.MachineID).
		SetPassword(string(hashPassword)).
		SetIpAddress(gctx.ClientIP()).
		Save(c.Ectx)

	if err != nil {
		log.Errorf("failed creating machine: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating machine"})
		return
	}
	gctx.JSON(http.StatusOK, gin.H{"data": machine})
	return
}

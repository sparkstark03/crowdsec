package controllers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) GetDecision(gctx *gin.Context) {
	var err error
	var results []models.Decision
	decisions := c.Client.Debug().Decision.Query().
		Where(decision.UntilGTE(time.Now()))
	for param, value := range gctx.Request.URL.Query() {
		switch param {
		case "scope":
			decisions = decisions.Where(decision.SourceScopeEQ(value[0]))
		case "value":
			decisions = decisions.Where(decision.SourceValueEQ(value[0]))
		case "type":
			decisions = decisions.Where(decision.DecisionTypeEQ(value[0]))
		default:
			gctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid parameter : %s", param)})
			return
		}
	}
	err = decisions.Select(
		decision.FieldUntil,
		decision.FieldScenario,
		decision.FieldDecisionType,
		decision.FieldSourceIpStart,
		decision.FieldSourceIpEnd,
		decision.FieldSourceValue,
		decision.FieldSourceScope,
	).Scan(c.Ectx, &results)
	if err != nil {
		log.Errorf("failed querying decisions: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed querying decision"})
		return
	}

	gctx.JSON(http.StatusOK, gin.H{"data": results})
}

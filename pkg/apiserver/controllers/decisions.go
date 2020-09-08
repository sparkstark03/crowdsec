package controllers

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/blocker"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) GetDecision(gctx *gin.Context) {
	var err error
	var results []models.Decision
	var data []*ent.Decision

	decisions := c.DBClient.Ent.Debug().Decision.Query().
		Where(decision.UntilGTE(time.Now()))
	for param, value := range gctx.Request.URL.Query() {
		switch param {
		case "scope":
			decisions = decisions.Where(decision.ScopeEQ(value[0]))
		case "value":
			decisions = decisions.Where(decision.TargetEQ(value[0]))
		case "type":
			decisions = decisions.Where(decision.TypeEQ(value[0]))
		default:
			gctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid parameter : %s", param)})
			return
		}
	}
	err = decisions.Select(
		decision.FieldUntil,
		decision.FieldScenario,
		decision.FieldType,
		decision.FieldStartIP,
		decision.FieldEndIP,
		decision.FieldTarget,
		decision.FieldScope,
	).Scan(c.Ectx, &data)
	if err != nil {
		log.Errorf("failed querying decisions: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed querying decision"})
		return
	}
	for _, dbDecision := range data {
		duration := dbDecision.Until.Sub(time.Now())
		decision := models.Decision{
			DecisionID: fmt.Sprintf("%d", dbDecision.ID),
			Duration:   duration.String(),
			EndIP:      dbDecision.EndIP,
			StartIP:    dbDecision.StartIP,
			Scenario:   dbDecision.Scenario,
			Scope:      dbDecision.Scope,
			Target:     dbDecision.Target,
			Type:       dbDecision.Type,
		}
		results = append(results, decision)
	}

	gctx.JSON(http.StatusOK, gin.H{"data": results})
}

func (c *Controller) StreamDecision(gctx *gin.Context) {
	var data []*ent.Decision

	ret := make(map[string][]*models.Decision, 0)
	ret["new"] = []*models.Decision{}
	ret["deleted"] = []*models.Decision{}

	if _, ok := gctx.Request.URL.Query()["startup"]; ok {
		data, err := c.DBClient.Ent.Debug().Decision.Query().All(c.Ectx)
		if err != nil {
			log.Errorf("failed querying decisions: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed querying decision"})
			return
		}
		for _, dbDecision := range data {
			duration := dbDecision.Until.Sub(time.Now())
			decision := &models.Decision{
				DecisionID: fmt.Sprintf("%d", dbDecision.ID),
				Duration:   duration.String(),
				EndIP:      dbDecision.EndIP,
				StartIP:    dbDecision.StartIP,
				Scenario:   dbDecision.Scenario,
				Scope:      dbDecision.Scope,
				Target:     dbDecision.Target,
				Type:       dbDecision.Type,
			}
			ret["new"] = append(ret["new"], decision)
		}
		gctx.JSON(http.StatusOK, ret)
		return
	}

	val, _ := gctx.Request.Header[c.APIKeyHeader]

	hashedKey := sha256.New()
	hashedKey.Write([]byte(val[0]))

	hashStr := fmt.Sprintf("%x", hashedKey.Sum(nil))
	results, err := c.DBClient.Ent.Blocker.Query().Where(blocker.APIKeyEQ(hashStr)).Select(blocker.FieldLastPull).Strings(c.Ectx)
	if err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
	}

	lastPullTime, err := time.Parse(time.RFC3339, results[0])
	if err != nil {
		log.Errorf("unable to convert last pull time '%s' to time.Time: %s", results[0], err)
	}

	data, err = c.DBClient.Ent.Debug().Decision.Query().Where(decision.CreatedAtGT(lastPullTime)).All(c.Ectx)
	if err != nil {
		log.Errorf("unable to get new decision for stream: %s", err)
		if err != nil {
			gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		}
	}
	for _, dbDecision := range data {
		duration := dbDecision.Until.Sub(time.Now())
		decision := &models.Decision{
			DecisionID: fmt.Sprintf("%d", dbDecision.ID),
			Duration:   duration.String(),
			EndIP:      dbDecision.EndIP,
			StartIP:    dbDecision.StartIP,
			Scenario:   dbDecision.Scenario,
			Scope:      dbDecision.Scope,
			Target:     dbDecision.Target,
			Type:       dbDecision.Type,
		}
		ret["new"] = append(ret["new"], decision)
	}

	data, err = c.DBClient.Ent.Debug().Decision.Query().Where(decision.UntilLT(time.Now())).All(c.Ectx)
	if err != nil {
		log.Errorf("unable to get old decision for stream: %s", err)
		if err != nil {
			gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		}
	}

	for _, dbDecision := range data {
		duration := dbDecision.Until.Sub(time.Now())
		decision := &models.Decision{
			DecisionID: fmt.Sprintf("%d", dbDecision.ID),
			Duration:   duration.String(),
			EndIP:      dbDecision.EndIP,
			StartIP:    dbDecision.StartIP,
			Scenario:   dbDecision.Scenario,
			Scope:      dbDecision.Scope,
			Target:     dbDecision.Target,
			Type:       dbDecision.Type,
		}
		ret["deleted"] = append(ret["deleted"], decision)
	}

	gctx.JSON(http.StatusOK, ret)
}

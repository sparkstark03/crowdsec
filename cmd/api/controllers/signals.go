package controllers

import (
	"github.com/crowdsecurity/crowdsec/cmd/api/ent/machine"
	"github.com/crowdsecurity/crowdsec/cmd/api/ent/signal"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
	"time"
)

type CreateSignalInput struct {
	MachineId    int        `json:"machineId" binding:"required"`
	Scenario     string     `json:"scenario" binding:"required"`
	BucketId     string     `json:"bucketId" binding:"required"`
	AlertMessage string     `json:"alertMessage" binding:"required"`
	EventCount   int        `json:"eventCount" binding:"required"`
	StartedAt    time.Time  `json:"startedAt" binding:"required"`
	StoppedAt    time.Time  `json:"stoppedAt" binding:"required"`
	SourceIp     string     `json:"sourceIp"`
	Capacity     int        `json:"capacity" binding:"required"`
	LeakSpeed    int        `json:"leakSpeed" binding:"required"`
	Reprocess    bool       `json:"reprocess"`
	Events       []Event    `json:"events" binding:"required"`
	Metas        []Meta     `json:"metas"`
	Decisions    []Decision `json:"decisions" binding:"required"`
}

type Event struct {
	Time       time.Time `json:"time"`
	Serialized string    `json:"serialized"`
}

type Meta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Decision struct {
	Until         time.Time `json:"until"`
	Reason        string    `json:"reason"`
	Scenario      string    `json:"scenario"`
	DecisionType  string    `json:"decisionType"`
	SourceIpStart int       `json:"sourceIpStart"`
	SourceIpEnd   int       `json:"sourceIpEnd"`
	SourceStr     string    `json:"sourceStr"`
	Scope         string    `json:"scope"`
}

func (c *Controller) CreateSignal(gctx *gin.Context) {
	var input CreateSignalInput
	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	machine, err := QueryMachine(c.Ectx, c.Client, input.MachineId)
	if err != nil {
		log.Errorf("failed query machine: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating signal, machineId not exist"})
		return
	}

	signal, err := c.Client.Signal.
		Create().
		SetScenario(input.Scenario).
		SetBucketId(input.BucketId).
		SetAlertMessage(input.AlertMessage).
		SetEventsCount(input.EventCount).
		SetStartedAt(input.StartedAt).
		SetStoppedAt(input.StoppedAt).
		SetSourceIp(input.SourceIp).
		SetCapacity(input.Capacity).
		SetLeakSpeed(input.LeakSpeed).
		SetReprocess(input.Reprocess).
		SetOwner(machine).
		Save(c.Ectx)
	if err != nil {
		log.Errorf("failed creating signal: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating signal"})
		return
	}

	if len(input.Events) > 0 {
		for _, eventItem := range input.Events {
			_, err := c.Client.Event.
				Create().
				SetTime(eventItem.Time).
				SetSerialized(eventItem.Serialized).
				SetOwner(signal).
				Save(c.Ectx)
			if err != nil {
				log.Errorf("failed creating event: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating signal"})
				return
			}
		}
	}

	if len(input.Metas) > 0 {
		for _, metaItem := range input.Metas {
			_, err := c.Client.Meta.
				Create().
				SetKey(metaItem.Key).
				SetValue(metaItem.Value).
				SetOwner(signal).
				Save(c.Ectx)
			if err != nil {
				log.Errorf("failed creating meta: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating signal"})
				return
			}
		}
	}

	if len(input.Decisions) > 0 {
		for _, decisionItem := range input.Decisions {
			_, err := c.Client.Decision.
				Create().
				SetUntil(decisionItem.Until).
				SetReason(decisionItem.Reason).
				SetScenario(decisionItem.Scenario).
				SetDecisionType(decisionItem.DecisionType).
				SetSourceIpStart(decisionItem.SourceIpStart).
				SetSourceIpEnd(decisionItem.SourceIpEnd).
				SetSourceStr(decisionItem.SourceStr).
				SetScope(decisionItem.Scope).
				SetOwner(signal).
				Save(c.Ectx)
			if err != nil {
				log.Errorf("failed creating decision: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating signal"})
				return
			}
		}
	}

	gctx.JSON(http.StatusOK, gin.H{"data": signal})
	return
}

func (c *Controller) FindSignals(gctx *gin.Context) {
	machineId := "machine1"
	scenario := gctx.Query("scenario")
	//scope := gctx.Query("scope")
	//sourceStr := gctx.Query("sourceStr")

	signals, err := c.Client.Machine.Query().
		Where(machine.MachineIdEQ(machineId)).
		QuerySignals().
		Where(signal.ScenarioEQ(scenario)).
		All(c.Ectx)
	if err != nil {
		log.Errorf("failed querying signal: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed querying signal"})
		return
	}

	gctx.JSON(http.StatusOK, gin.H{"data": signals})
	return
}

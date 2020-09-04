package controllers

import (
	"fmt"
	"github.com/crowdsecurity/crowdsec/cmd/api/ent"
	"github.com/crowdsecurity/crowdsec/cmd/api/ent/alert"
	"github.com/crowdsecurity/crowdsec/cmd/api/ent/decision"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"time"
)

type CreateAlertInput struct {
	MachineId  int        `json:"machine_id" binding:"required"`
	Scenario   string     `json:"scenario" binding:"required"`
	BucketId   string     `json:"bucket_id" binding:"required"`
	Message    string     `json:"message" binding:"required"`
	EventCount int        `json:"event_count" binding:"required"`
	StartedAt  time.Time  `json:"started_at" binding:"required"`
	StoppedAt  time.Time  `json:"stopped_at" binding:"required"`
	Capacity   int        `json:"capacity" binding:"required"`
	LeakSpeed  int        `json:"leak_speed" binding:"required"`
	Reprocess  bool       `json:"reprocess"`
	Source     Source     `json:"source" binding:"required"`
	Events     []Event    `json:"events" binding:"required"`
	Metas      []Meta     `json:"metas"`
	Decisions  []Decision `json:"decisions" binding:"required"`
}

type Event struct {
	Time       time.Time `json:"time"`
	Serialized string    `json:"serialized"`
}

type Source struct {
	Scope     string  `json:"scope" binding:"required"`
	Value     string  `json:"value" binding:"required"`
	Ip        string  `json:"ip"`
	Range     string  `json:"range"`
	AsNumber  string  `json:"as_number"`
	AsName    string  `json:"as_name"`
	Country   string  `json:"country"`
	Latitude  float32 `json:"latitude"`
	Longitude float32 `json:"longitude"`
}

type Meta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Decision struct {
	Until         time.Time `json:"until"`
	Scenario      string    `json:"scenario"`
	DecisionType  string    `json:"decision_type"`
	SourceIpStart uint32    `json:"source_ip_start"`
	SourceIpEnd   uint32    `json:"source_ip_end"`
	SourceValue   string    `json:"source_value"`
	SourceScope   string    `json:"source_scope"`
}

func (c *Controller) CreateAlert(gctx *gin.Context) {
	var input CreateAlertInput
	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	machine, err := QueryMachine(c.Ectx, c.Client, input.MachineId)
	if err != nil {
		log.Errorf("failed query machine: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert, machineId not exist"})
		return
	}

	alert, err := c.Client.Alert.
		Create().
		SetScenario(input.Scenario).
		SetBucketId(input.BucketId).
		SetMessage(input.Message).
		SetEventsCount(input.EventCount).
		SetStartedAt(input.StartedAt).
		SetStoppedAt(input.StoppedAt).
		SetSourceScope(input.Source.Scope).
		SetSourceValue(input.Source.Value).
		SetSourceIp(input.Source.Ip).
		SetSourceRange(input.Source.Range).
		SetSourceAsNumber(input.Source.AsNumber).
		SetSourceAsName(input.Source.AsName).
		SetSourceCountry(input.Source.Country).
		SetSourceLatitude(input.Source.Latitude).
		SetSourceLongitude(input.Source.Longitude).
		SetCapacity(input.Capacity).
		SetLeakSpeed(input.LeakSpeed).
		SetReprocess(input.Reprocess).
		SetOwner(machine).
		Save(c.Ectx)
	if err != nil {
		log.Errorf("failed creating alert: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
		return
	}

	if len(input.Events) > 0 {
		for _, eventItem := range input.Events {
			_, err := c.Client.Event.
				Create().
				SetTime(eventItem.Time).
				SetSerialized(eventItem.Serialized).
				SetOwner(alert).
				Save(c.Ectx)
			if err != nil {
				log.Errorf("failed creating event: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
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
				SetOwner(alert).
				Save(c.Ectx)
			if err != nil {
				log.Errorf("failed creating meta: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
				return
			}
		}
	}

	if len(input.Decisions) > 0 {
		for _, decisionItem := range input.Decisions {
			_, err := c.Client.Decision.
				Create().
				SetUntil(decisionItem.Until).
				SetScenario(decisionItem.Scenario).
				SetDecisionType(decisionItem.DecisionType).
				SetSourceIpStart(decisionItem.SourceIpStart).
				SetSourceIpEnd(decisionItem.SourceIpEnd).
				SetSourceValue(decisionItem.SourceValue).
				SetSourceScope(decisionItem.SourceScope).
				SetOwner(alert).
				Save(c.Ectx)
			if err != nil {
				log.Errorf("failed creating decision: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
				return
			}
		}
	}

	gctx.JSON(http.StatusOK, gin.H{"data": alert})
	return
}

func (c *Controller) FindAlerts(gctx *gin.Context) {
	var err error
	var startIp uint32
	var endIp uint32
	var hasActiveDecision bool
	layout := "2006-01-02T15:04:05.000Z"
	alerts := c.Client.Debug().Alert.Query()
	for param, value := range gctx.Request.URL.Query() {
		switch param {
		case "source_scope":
			alerts = alerts.Where(alert.SourceScopeEQ(value[0]))
		case "source_value":
			alerts = alerts.Where(alert.SourceValueEQ(value[0]))
		case "scenario":
			alerts = alerts.Where(alert.ScenarioEQ(value[0]))
		case "ip":
			isValidIp := IsIpv4(value[0])
			if !isValidIp {
				log.Errorf("failed querying alerts: Ip %v is not valid", value[0])
				gctx.JSON(http.StatusBadRequest, gin.H{"error": "ip is not valid"})
				return
			}
			startIp, endIp, err = GetIpsFromIpRange(value[0] + "/32")
			if err != nil {
				log.Errorf("failed querying alerts: Range %v is not valid", value[0])
			}
		case "range":
			startIp, endIp, err = GetIpsFromIpRange(value[0])
			if err != nil {
				log.Errorf("failed querying alerts: Range %v is not valid", value[0])
				gctx.JSON(http.StatusBadRequest, gin.H{"error": "Range is not valid"})
				return
			}
		case "since":
			since, err := time.Parse(layout, value[0])
			if err != nil {
				log.Errorln(err)
				gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			alerts = alerts.Where(alert.CreatedAtGTE(since))
		case "until":
			until, err := time.Parse(layout, value[0])
			if err != nil {
				log.Errorln(err)
				gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			alerts = alerts.Where(alert.CreatedAtLTE(until))
		case "has_active_decision":
			if hasActiveDecision, err = strconv.ParseBool(value[0]); err != nil {
				log.Errorf("failed querying alerts: Bool %v is not valid", value[0])
				gctx.JSON(http.StatusBadRequest, gin.H{"error": "has_active_decision param not valid"})
				return
			}
			if hasActiveDecision {
				alerts = alerts.Where(alert.HasDecisionsWith(decision.UntilGTE(time.Now())))
			}
		default:
			gctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid parameter : %s", param)})
		}
	}
	if startIp != 0 && endIp != 0 {
		alerts = alerts.Where(alert.And(
			alert.HasDecisionsWith(decision.SourceIpStartGTE(startIp)),
			alert.HasDecisionsWith(decision.SourceIpEndLTE(endIp)),
		))
	}
	alerts = alerts.
		WithDecisions().
		WithEvents().
		WithMetas().
		WithOwner()

	result, err := alerts.
		Order(ent.Asc(alert.FieldCreatedAt)).
		All(c.Ectx)
	if err != nil {
		log.Errorf("failed querying alerts: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed querying alert"})
		return
	}
	gctx.JSON(http.StatusOK, gin.H{"data": result})
	return
}

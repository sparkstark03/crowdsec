package controllers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func FormatAlert(result []*ent.Alert) []models.Alert {
	var data []models.Alert
	for _, alertItem := range result {
		var outputAlert models.Alert
		outputAlert = models.Alert{
			MachineID:   alertItem.Edges.Owner.MachineId,
			Scenario:    alertItem.Scenario,
			AlertID:     alertItem.BucketId,
			Message:     alertItem.Message,
			EventsCount: alertItem.EventsCount,
			StartAt:     alertItem.StartedAt,
			StopAt:      alertItem.StoppedAt,
			Capacity:    alertItem.Capacity,
			Leakspeed:   alertItem.LeakSpeed,
			//Reprocess:   alertItem.Reprocess,
			Source: &models.Source{
				Scope:    alertItem.SourceScope,
				Value:    alertItem.SourceValue,
				IP:       alertItem.SourceIp,
				Range:    alertItem.SourceRange,
				AsNumber: alertItem.SourceAsNumber,
				AsName:   alertItem.SourceAsName,
				Cn:       alertItem.SourceCountry,
				Lat:      alertItem.SourceLatitude,
				Long:     alertItem.SourceLongitude,
			},
		}
		for _, eventItem := range alertItem.Edges.Events {
			var outputEvents []models.Event
			outputEvents = append(outputEvents, models.Event{
				Timestamp: eventItem.Time,
				Meta:      eventItem.Serialized,
			})
			outputAlert.Events = outputEvents
		}
		for _, metaItem := range alertItem.Edges.Metas {
			var outputMetas []*models.Meta
			outputMetas = append(outputMetas, &models.Meta{
				Key:   metaItem.Key,
				Value: metaItem.Value,
			})
			outputAlert.Meta = outputMetas
		}
		for _, decisionItem := range alertItem.Edges.Decisions {
			var outputDecisions []*models.Decision
			outputDecisions = append(outputDecisions, &models.Decision{
				Duration: decisionItem.Duration, // transform into time.Time ?
				Scenario: decisionItem.Scenario,
				Type:     decisionItem.DecisionType,
				StartIP:  int64(decisionItem.SourceIpStart),
				EndIP:    int64(decisionItem.SourceIpEnd),
				Scope:    decisionItem.SourceScope,
				Target:   decisionItem.SourceValue,
			})
			outputAlert.Decisions = outputDecisions
		}
		data = append(data, outputAlert)
	}
	return data
}

func (c *Controller) CreateAlert(gctx *gin.Context) {
	var input models.Alert
	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	machine, err := machines.QueryMachine(c.Ectx, c.Client, input.MachineId)
	if err != nil {
		log.Errorf("failed query machine: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert, machineId not exist"})
		return
	}

	alert, err := c.Client.Alert.
		Create().
		SetScenario(input.Scenario).
		SetBucketId(input.AlertID).
		SetMessage(input.Message).
		SetEventsCount(input.EventsCount).
		SetStartedAt(input.StartAt).
		SetStoppedAt(input.StopAt).
		SetSourceScope(input.Source.Scope).
		SetSourceValue(input.Source.Value).
		SetSourceIp(input.Source.IP).
		SetSourceRange(input.Source.Range).
		SetSourceAsNumber(input.Source.AsNumber).
		SetSourceAsName(input.Source.AsName).
		SetSourceCountry(input.Source.Cn).
		SetSourceLatitude(input.Source.Lat).
		SetSourceLongitude(input.Source.Long).
		SetCapacity(input.Capacity).
		SetLeakSpeed(input.Leakspeed).
		//SetReprocess(input.Reprocess).
		SetOwner(machine).
		Save(c.Ectx)
	if err != nil {
		log.Errorf("failed creating alert: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
		return
	}

	if len(input.Events) > 0 {
		bulk := make([]*ent.EventCreate, len(input.Events))
		for i, eventItem := range input.Events {
			bulk[i] = c.Client.Event.Create().
				SetTime(eventItem.Timestamp).
				SetSerialized(eventItem.Meta).
				SetOwner(alert)
		}
		_, err := c.Client.Event.CreateBulk(bulk...).Save(c.Ectx)
		if err != nil {
			log.Errorf("failed creating event: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
			return
		}
	}

	if len(input.Metas) > 0 {
		bulk := make([]*ent.MetaCreate, len(input.Metas))
		for i, metaItem := range input.Metas {
			bulk[i] = c.Client.Meta.Create().
				SetKey(metaItem.Key).
				SetValue(metaItem.Value).
				SetOwner(alert)
		}
		_, err := c.Client.Meta.CreateBulk(bulk...).Save(c.Ectx)
		if err != nil {
			log.Errorf("failed creating meta: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
			return
		}
	}

	if len(input.Decisions) > 0 {
		bulk := make([]*ent.DecisionCreate, len(input.Decisions))
		for i, decisionItem := range input.Decisions {
			bulk[i] = c.Client.Decision.Create().
				SetUntil(decisionItem.Until).
				SetScenario(decisionItem.Scenario).
				SetDecisionType(decisionItem.DecisionType).
				SetSourceIpStart(decisionItem.SourceIpStart).
				SetSourceIpEnd(decisionItem.SourceIpEnd).
				SetSourceValue(decisionItem.SourceValue).
				SetSourceScope(decisionItem.SourceScope).
				SetOwner(alert)
		}
		_, err := c.Client.Decision.CreateBulk(bulk...).Save(c.Ectx)
		if err != nil {
			log.Errorf("failed creating decision: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
			return
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
			since, err := time.Parse(time.RFC3339, value[0])
			if err != nil {
				log.Errorln(err)
				gctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid since param format '%s'", value[0])})
				return
			}
			alerts = alerts.Where(alert.CreatedAtGTE(since))
		case "until":
			until, err := time.Parse(time.RFC3339, value[0])
			if err != nil {
				log.Errorln(err)
				gctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid until param format '%s'", value[0])})
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
			return
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

	data := FormatAlert(result)

	gctx.JSON(http.StatusOK, gin.H{"data": data})
	return
}

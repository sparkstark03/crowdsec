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

func FormatAlert(result []*ent.Alert) []AlertInput {
	var data []AlertInput
	for _, alertItem := range result {
		var outputAlert AlertInput
		outputAlert = AlertInput{
			MachineId:  alertItem.Edges.Owner.MachineId,
			Scenario:   alertItem.Scenario,
			BucketId:   alertItem.BucketId,
			Message:    alertItem.Message,
			EventCount: alertItem.EventsCount,
			StartedAt:  alertItem.StartedAt,
			StoppedAt:  alertItem.StoppedAt,
			Capacity:   alertItem.Capacity,
			LeakSpeed:  alertItem.LeakSpeed,
			Reprocess:  alertItem.Reprocess,
			Source: Source{
				Scope:     alertItem.SourceScope,
				Value:     alertItem.SourceValue,
				Ip:        alertItem.SourceIp,
				Range:     alertItem.SourceRange,
				AsNumber:  alertItem.SourceAsNumber,
				AsName:    alertItem.SourceAsName,
				Country:   alertItem.SourceCountry,
				Latitude:  alertItem.SourceLatitude,
				Longitude: alertItem.SourceLongitude,
			},
		}
		for _, eventItem := range alertItem.Edges.Events {
			var outputEvents []Event
			outputEvents = append(outputEvents, Event{
				Time:       eventItem.Time,
				Serialized: eventItem.Serialized,
			})
			outputAlert.Events = outputEvents
		}
		for _, metaItem := range alertItem.Edges.Metas {
			var outputMetas []Meta
			outputMetas = append(outputMetas, Meta{
				Key:   metaItem.Key,
				Value: metaItem.Value,
			})
			outputAlert.Metas = outputMetas
		}
		for _, decisionItem := range alertItem.Edges.Decisions {
			var outputDecisions []Decision
			outputDecisions = append(outputDecisions, Decision{
				Until:         decisionItem.Until,
				Scenario:      decisionItem.Scenario,
				DecisionType:  decisionItem.DecisionType,
				SourceIpStart: decisionItem.SourceIpStart,
				SourceIpEnd:   decisionItem.SourceIpEnd,
				SourceScope:   decisionItem.SourceScope,
				SourceValue:   decisionItem.SourceValue,
			})
			outputAlert.Decisions = outputDecisions
		}
		data = append(data, outputAlert)
	}
	return data
}

func ValidateAlertInput(gctx *gin.Context, alerts *ent.AlertQuery) (*ent.AlertQuery, error) {
	var err error
	var startIp uint32
	var endIp uint32
	var hasActiveDecision bool
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
				return nil, fmt.Errorf("ip is not valid")
			}
			startIp, endIp, err = GetIpsFromIpRange(value[0] + "/32")
			if err != nil {
				log.Errorf("failed querying alerts: Range %v is not valid", value[0])
			}
		case "range":
			startIp, endIp, err = GetIpsFromIpRange(value[0])
			if err != nil {
				log.Errorf("failed querying alerts: Range %v is not valid", value[0])
				return nil, fmt.Errorf("Range is not valid")
			}
		case "since":
			since, err := time.Parse(time.RFC3339, value[0])
			if err != nil {
				log.Errorln(err)
				return nil, fmt.Errorf("Invalid since param format '%s'", value[0])
			}
			alerts = alerts.Where(alert.CreatedAtGTE(since))
		case "until":
			until, err := time.Parse(time.RFC3339, value[0])
			if err != nil {
				log.Errorln(err)
				return nil, fmt.Errorf("Invalid until param format '%s'", value[0])
			}
			alerts = alerts.Where(alert.CreatedAtLTE(until))
		case "has_active_decision":
			if hasActiveDecision, err = strconv.ParseBool(value[0]); err != nil {
				log.Errorf("failed querying alerts: Bool %v is not valid", value[0])
				return nil, fmt.Errorf("has_active_decision param not valid")
			}
			if hasActiveDecision {
				alerts = alerts.Where(alert.HasDecisionsWith(decision.UntilGTE(time.Now())))
			}
		default:
			return nil, fmt.Errorf("invalid parameter : %s", param)
		}
	}
	if startIp != 0 && endIp != 0 {
		alerts = alerts.Where(alert.And(
			alert.HasDecisionsWith(decision.SourceIpStartGTE(startIp)),
			alert.HasDecisionsWith(decision.SourceIpEndLTE(endIp)),
		))
	}
	return alerts, nil
}

func (c *Controller) CreateAlert(gctx *gin.Context) {
	var input []AlertInput
	var response []*ent.Alert
	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, alertItem := range input {
		machine, err := QueryMachine(c.Ectx, c.Client, alertItem.MachineId)
		if err != nil {
			log.Errorf("failed query machine: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert, machineId not exist"})
			return
		}

		alert, err := c.Client.Alert.
			Create().
			SetScenario(alertItem.Scenario).
			SetBucketId(alertItem.BucketId).
			SetMessage(alertItem.Message).
			SetEventsCount(alertItem.EventCount).
			SetStartedAt(alertItem.StartedAt).
			SetStoppedAt(alertItem.StoppedAt).
			SetSourceScope(alertItem.Source.Scope).
			SetSourceValue(alertItem.Source.Value).
			SetSourceIp(alertItem.Source.Ip).
			SetSourceRange(alertItem.Source.Range).
			SetSourceAsNumber(alertItem.Source.AsNumber).
			SetSourceAsName(alertItem.Source.AsName).
			SetSourceCountry(alertItem.Source.Country).
			SetSourceLatitude(alertItem.Source.Latitude).
			SetSourceLongitude(alertItem.Source.Longitude).
			SetCapacity(alertItem.Capacity).
			SetLeakSpeed(alertItem.LeakSpeed).
			SetReprocess(alertItem.Reprocess).
			SetOwner(machine).
			Save(c.Ectx)
		if err != nil {
			log.Errorf("failed creating alert: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
			return
		}

		if len(alertItem.Events) > 0 {
			bulk := make([]*ent.EventCreate, len(alertItem.Events))
			for i, eventItem := range alertItem.Events {
				bulk[i] = c.Client.Event.Create().
					SetTime(eventItem.Time).
					SetSerialized(eventItem.Serialized).
					SetOwner(alert)
			}
			_, err := c.Client.Event.CreateBulk(bulk...).Save(c.Ectx)
			if err != nil {
				log.Errorf("failed creating event: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
				return
			}
		}

		if len(alertItem.Metas) > 0 {
			bulk := make([]*ent.MetaCreate, len(alertItem.Metas))
			for i, metaItem := range alertItem.Metas {
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

		if len(alertItem.Decisions) > 0 {
			bulk := make([]*ent.DecisionCreate, len(alertItem.Decisions))
			for i, decisionItem := range alertItem.Decisions {
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
		response = append(response, alert)
	}

	gctx.JSON(http.StatusOK, gin.H{"data": response})
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
	alerts, err = ValidateAlertInput(gctx, alerts)
	if err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
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

func (c *Controller) DeleteAlerts(gctx *gin.Context) {
	var err error
	var startIp uint32
	var endIp uint32
	var hasActiveDecision bool
	alerts := c.Client.Debug().Alert.Delete()
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

	deletedNb, err := alerts.Exec(c.Ectx)
	if err != nil {
		log.Errorf("failed deleting alerts: %v", err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed deleting alerts"})
		return
	}

	gctx.JSON(http.StatusOK, gin.H{"deleted": deletedNb})
	return
}

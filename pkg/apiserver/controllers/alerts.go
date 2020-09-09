package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/event"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/meta"
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
			StartAt:     alertItem.StartedAt.String(),
			StopAt:      alertItem.StoppedAt.String(),
			Capacity:    alertItem.Capacity,
			Leakspeed:   alertItem.LeakSpeed,
			Source: &models.Source{
				Scope:     alertItem.SourceScope,
				Value:     alertItem.SourceValue,
				IP:        alertItem.SourceIp,
				Range:     alertItem.SourceRange,
				AsNumber:  alertItem.SourceAsNumber,
				AsName:    alertItem.SourceAsName,
				Cn:        alertItem.SourceCountry,
				Latitude:  alertItem.SourceLatitude,
				Longitude: alertItem.SourceLongitude,
			},
		}
		for _, eventItem := range alertItem.Edges.Events {
			var outputEvents []*models.Event
			var Metas models.Meta
			if err := json.Unmarshal([]byte(eventItem.Serialized), &Metas); err != nil {
				log.Errorf("unable to unmarshall events meta '%s' : %s", eventItem.Serialized, err)
			}
			outputEvents = append(outputEvents, &models.Event{
				Timestamp: eventItem.Time.String(),
				Meta:      Metas,
			})
			outputAlert.Events = outputEvents
		}
		for _, metaItem := range alertItem.Edges.Metas {
			var outputMetas models.Meta
			outputMetas = append(outputMetas, &models.MetaItems0{
				Key:   metaItem.Key,
				Value: metaItem.Value,
			})
			outputAlert.Meta = outputMetas
		}
		for _, decisionItem := range alertItem.Edges.Decisions {
			var outputDecisions []*models.Decision
			outputDecisions = append(outputDecisions, &models.Decision{
				Duration: decisionItem.Until.Sub(time.Now()).String(), // transform into time.Time ?
				Scenario: decisionItem.Scenario,
				Type:     decisionItem.Type,
				StartIP:  decisionItem.StartIP,
				EndIP:    decisionItem.EndIP,
				Scope:    decisionItem.Scope,
				Target:   decisionItem.Target,
			})
			outputAlert.Decisions = outputDecisions
		}
		data = append(data, outputAlert)
	}
	return data
}

func ErrorMessageAlertDeletion(err error, gctx *gin.Context) {
	log.Errorf("failed deleting alerts: %v", err)
	gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed deleting alerts"})
	return
}

func BuildAlertRequest(alerts *ent.AlertQuery, gctx *gin.Context) (*ent.AlertQuery, error) {
	var err error
	var startIP int64
	var endIP int64
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
			isValidIP := IsIpv4(value[0])
			if !isValidIP {
				log.Errorf("failed querying alerts: Ip %v is not valid", value[0])
				return nil, fmt.Errorf("ip is not valid")
			}
			startIP, endIP, err = GetIpsFromIpRange(value[0] + "/32")
			if err != nil {
				log.Errorf("failed querying alerts: Range %v is not valid", value[0])
			}
		case "range":
			startIP, endIP, err = GetIpsFromIpRange(value[0])
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
				gctx.JSON(http.StatusBadRequest, gin.H{"error": "has_active_decision param not valid"})
				return nil, fmt.Errorf("has_active_decision param not valid")
			}
			if hasActiveDecision {
				alerts = alerts.Where(alert.HasDecisionsWith(decision.UntilGTE(time.Now())))
			}
		default:
			gctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid parameter : %s", param)})
			return nil, fmt.Errorf("invalid parameter : %s", param)
		}
	}
	if startIP != 0 && endIP != 0 {
		alerts = alerts.Where(alert.And(
			alert.HasDecisionsWith(decision.StartIPGTE(startIP)),
			alert.HasDecisionsWith(decision.EndIP(endIP)),
		))
	}
	return alerts, nil
}

func (c *Controller) CreateAlert(gctx *gin.Context) {
	var input []models.Alert
	var responses []map[string]string
	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	for _, alertItem := range input {

		machine, err := QueryMachine(c.Ectx, c.DBClient.Ent, alertItem.MachineID)
		if err != nil {
			log.Errorf("failed query machine: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert, machineId not exist"})
			return
		}

		startAtTime, err := time.Parse(time.RFC3339, alertItem.StartAt)
		if err != nil {
			log.Errorf("unable to parse start at time '%s': %s", alertItem.StartAt, err)
		}

		stopAtTime, err := time.Parse(time.RFC3339, alertItem.StopAt)
		if err != nil {
			log.Errorf("unable to parse stop at time '%s': %s", alertItem.StopAt, err)
		}

		alert, err := c.DBClient.Ent.Alert.
			Create().
			SetScenario(alertItem.Scenario).
			SetBucketId(alertItem.AlertID).
			SetMessage(alertItem.Message).
			SetEventsCount(alertItem.EventsCount).
			SetStartedAt(startAtTime).
			SetStoppedAt(stopAtTime).
			SetSourceScope(alertItem.Source.Scope).
			SetSourceValue(alertItem.Source.Value).
			SetSourceIp(alertItem.Source.IP).
			SetSourceRange(alertItem.Source.Range).
			SetSourceAsNumber(alertItem.Source.AsNumber).
			SetSourceAsName(alertItem.Source.AsName).
			SetSourceCountry(alertItem.Source.Cn).
			SetSourceLatitude(alertItem.Source.Latitude).
			SetSourceLongitude(alertItem.Source.Longitude).
			SetCapacity(alertItem.Capacity).
			SetLeakSpeed(alertItem.Leakspeed).
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
				ts, err := time.Parse(time.RFC3339, eventItem.Timestamp)
				if err != nil {
					log.Errorf("unable to parse event item timestamp '%s': %s", eventItem.Timestamp, err)
				}
				marshallMetas, err := json.Marshal(eventItem.Meta)
				if err != nil {
					log.Errorf("unable to marshal metas '%s' : %s", eventItem.Meta, err)
				}

				bulk[i] = c.DBClient.Ent.Event.Create().
					SetTime(ts).
					SetSerialized(string(marshallMetas)).
					SetOwner(alert)
			}
			_, err := c.DBClient.Ent.Event.CreateBulk(bulk...).Save(c.Ectx)
			if err != nil {
				log.Errorf("failed creating event: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
				return
			}
		}

		if len(alertItem.Meta) > 0 {
			bulk := make([]*ent.MetaCreate, len(alertItem.Meta))
			for i, metaItem := range alertItem.Meta {
				bulk[i] = c.DBClient.Ent.Meta.Create().
					SetKey(metaItem.Key).
					SetValue(metaItem.Value).
					SetOwner(alert)
			}
			_, err := c.DBClient.Ent.Meta.CreateBulk(bulk...).Save(c.Ectx)
			if err != nil {
				log.Errorf("failed creating meta: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
				return
			}
		}

		if len(alertItem.Decisions) > 0 {
			bulk := make([]*ent.DecisionCreate, len(alertItem.Decisions))
			for i, decisionItem := range alertItem.Decisions {
				duration, err := time.ParseDuration(decisionItem.Duration)
				if err != nil {
					log.Errorf("unable to parse decision duration '%s': %s", decisionItem.Duration, err)
					continue
				}
				bulk[i] = c.DBClient.Ent.Decision.Create().
					SetUntil(time.Now().Add(duration)).
					SetScenario(decisionItem.Scenario).
					SetType(decisionItem.Type).
					SetStartIP(decisionItem.StartIP).
					SetEndIP(decisionItem.EndIP).
					SetTarget(decisionItem.Target).
					SetScope(decisionItem.Scope).
					SetOwner(alert)
			}
			_, err := c.DBClient.Ent.Decision.CreateBulk(bulk...).Save(c.Ectx)
			if err != nil {
				log.Errorf("failed creating decision: %v", err)
				gctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed creating alert"})
				return
			}
		}
		resp := make(map[string]string)
		alertID := strconv.Itoa(alert.ID)
		resp["alert_id"] = alertID
		responses = append(responses, resp)
	}

	gctx.JSON(http.StatusOK, responses)
	return
}

func (c *Controller) FindAlerts(gctx *gin.Context) {
	alerts := c.DBClient.Ent.Debug().Alert.Query()
	alerts, err := BuildAlertRequest(alerts, gctx)
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

	gctx.JSON(http.StatusOK, data)
	return
}

func (c *Controller) DeleteAlerts(gctx *gin.Context) {
	var err error
	alerts := c.DBClient.Ent.Debug().Alert.Query()
	alerts, err = BuildAlertRequest(alerts, gctx)
	results, err := alerts.
		Order(ent.Asc(alert.FieldCreatedAt)).
		All(c.Ectx)
	for _, alertItem := range results {
		_, err = c.DBClient.Ent.Event.Delete().
			Where(event.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(c.Ectx)
		if err != nil {
			ErrorMessageAlertDeletion(err, gctx)
		}
		_, err = c.DBClient.Ent.Meta.Delete().
			Where(meta.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(c.Ectx)
		if err != nil {
			ErrorMessageAlertDeletion(err, gctx)
		}
		_, err = c.DBClient.Ent.Decision.Delete().
			Where(decision.HasOwnerWith(alert.IDEQ(alertItem.ID))).Exec(c.Ectx)
		if err != nil {
			ErrorMessageAlertDeletion(err, gctx)
		}
		err = c.DBClient.Ent.Alert.DeleteOne(alertItem).Exec(c.Ectx)
		if err != nil {
			ErrorMessageAlertDeletion(err, gctx)
		}
	}

	gctx.JSON(http.StatusOK, gin.H{"deleted": len(results)})
	return
}

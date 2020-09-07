package apiclient

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// type ApiAlerts service

type AlertsService service

func (c *AlertsService) Add(ctx context.Context) (*models.AddAlertsResponse, *Response, error) {
	return nil, nil, nil
}

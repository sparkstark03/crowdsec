package apiclient

import (
	"context"
	"log"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// type ApiAlerts service

type AlertsService service

func (s *AlertsService) Add(ctx context.Context, alerts models.AddAlertsRequest) (*models.AddAlertsResponse, *Response, error) {

	var added_ids models.AddAlertsResponse

	log.Printf("ratatatatatat")
	u := "alerts"
	req, err := s.client.NewRequest("POST", u, &alerts)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.client.Do(ctx, req, &added_ids)
	if err != nil {
		return nil, resp, err
	}
	return &added_ids, resp, nil
}

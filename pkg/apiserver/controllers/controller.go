package controllers

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

type Controller struct {
	Ectx         context.Context
	Client       *ent.Client
	APIKeyHeader string
}

func New(ctx context.Context, client *ent.Client, APIKeyHeader string) *Controller {
	return &Controller{
		Ectx:         ctx,
		Client:       client,
		APIKeyHeader: APIKeyHeader,
	}
}

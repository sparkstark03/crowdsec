package controllers

import (
	"context"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

type Controller struct {
	Ectx   context.Context
	Client *ent.Client
}

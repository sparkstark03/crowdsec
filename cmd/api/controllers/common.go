package controllers

import (
	"context"
	"github.com/crowdsecurity/crowdsec/cmd/api/ent"
)

type Controller struct {
	Ectx   context.Context
	Client *ent.Client
}

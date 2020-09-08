package controllers

import (
	"context"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

type Controller struct {
	Ectx   context.Context
	Client *ent.Client
}

type AlertInput struct {
	MachineId  string     `json:"machine_id" binding:"required"`
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

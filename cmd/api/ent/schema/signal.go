package schema

import (
	"github.com/facebook/ent"
	"github.com/facebook/ent/schema/edge"
	"github.com/facebook/ent/schema/field"
	"time"
)

// Signal holds the schema definition for the Signal entity.
type Signal struct {
	ent.Schema
}

// Fields of the Signal.
func (Signal) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now),
		field.String("scenario"),
		field.String("bucketId"),
		field.String("alertMessage"),
		field.Int("eventsCount"),
		field.Time("startedAt"),
		field.Time("stoppedAt"),
		field.String("sourceIp").
			Optional(),
		field.String("sourceRange").
			Optional(),
		field.String("sourceAsNumber").
			Optional(),
		field.String("sourceAsName").
			Optional(),
		field.String("sourceCountry").
			Optional(),
		field.Float32("sourceLatitude").
			Optional(),
		field.Float32("sourceLongitude").
			Optional(),
		field.Int("Capacity"),
		field.Int("leakSpeed"),
		field.Bool("reprocess"),
	}
}

// Edges of the Signal.
func (Signal) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", Machine.Type).
			Ref("signals").
			Unique(),
		edge.To("decisions", Decision.Type),
		edge.To("events", Event.Type),
		edge.To("metas", Meta.Type),
	}
}

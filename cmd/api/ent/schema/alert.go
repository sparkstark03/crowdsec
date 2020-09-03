package schema

import (
	"github.com/facebook/ent"
	"github.com/facebook/ent/schema/edge"
	"github.com/facebook/ent/schema/field"
	"time"
)

// Alert holds the schema definition for the Alert entity.
type Alert struct {
	ent.Schema
}

// Fields of the Alert.
func (Alert) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now),
		field.String("scenario"),
		field.String("bucketId"),
		field.String("message"),
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
		field.String("sourceScope"),
		field.String("sourceValue"),
		field.Int("capacity"),
		field.Int("leakSpeed"),
		field.Bool("reprocess"),
	}
}

// Edges of the Alert.
func (Alert) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", Machine.Type).
			Ref("signals").
			Unique(),
		edge.To("decisions", Decision.Type),
		edge.To("events", Event.Type),
		edge.To("metas", Meta.Type),
	}
}

package schema

import (
	"github.com/facebook/ent"
	"github.com/facebook/ent/schema/edge"
	"github.com/facebook/ent/schema/field"
	"time"
)

// Decision holds the schema definition for the Decision entity.
type Decision struct {
	ent.Schema
}

// Fields of the Decision.
func (Decision) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now),
		field.Time("until"),
		field.String("reason"),
		field.String("scenario"),
		field.String("decisionType"),
		field.Int("sourceIpStart"),
		field.Int("sourceIpEnd"),
		field.String("sourceStr"),
		field.String("scope"),
	}
}

// Edges of the Decision.
func (Decision) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", Signal.Type).
			Ref("decisions").
			Unique(),
	}
}

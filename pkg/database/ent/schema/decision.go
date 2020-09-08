package schema

import (
	"time"

	"github.com/facebook/ent"
	"github.com/facebook/ent/schema/edge"
	"github.com/facebook/ent/schema/field"
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
		field.String("scenario"),
		field.String("decisionType"),
		field.Int64("sourceIpStart").Optional(),
		field.Int64("sourceIpEnd").Optional(),
		field.String("sourceScope"),
		field.String("sourceValue"),
	}
}

// Edges of the Decision.
func (Decision) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", Alert.Type).
			Ref("decisions").
			Unique(),
	}
}

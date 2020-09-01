package schema

import (
	"github.com/facebook/ent"
	"github.com/facebook/ent/schema/edge"
	"github.com/facebook/ent/schema/field"
	"time"
)

// Machine holds the schema definition for the Machine entity.
type Machine struct {
	ent.Schema
}

// Fields of the Machine.
func (Machine) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now),
		field.String("machineId"),
		field.String("password"),
		field.String("ipAddress"),
	}
}

// Edges of the Machine.
func (Machine) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("signals", Signal.Type),
	}
}

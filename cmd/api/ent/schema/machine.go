package schema

import (
	"github.com/facebook/ent"
	"github.com/facebook/ent/schema/field"
)

// Machine holds the schema definition for the Machine entity.
type Machine struct {
	ent.Schema
}

// Fields of the Machine.
func (Machine) Fields() []ent.Field {
	return []ent.Field{
		field.String("machineId"),
		field.String("password"),
		field.String("token"),
		field.String("ipAddress"),
	}
}

// Edges of the Machine.
func (Machine) Edges() []ent.Edge {
	return nil
}

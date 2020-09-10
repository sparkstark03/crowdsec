package database

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/pkg/errors"
)

func BuildDecisionRequestWithFilter(query *ent.DecisionQuery, filter map[string][]string) (*ent.DecisionQuery, error) {
	for param, value := range filter {
		switch param {
		case "scope":
			query = query.Where(decision.ScopeEQ(value[0]))
		case "value":
			query = query.Where(decision.TargetEQ(value[0]))
		case "type":
			query = query.Where(decision.TypeEQ(value[0]))
		default:
			return query, errors.Wrap(InvalidFilter, fmt.Sprintf("'%s' doesn't exist", param))
		}
	}
	return query, nil
}

func (c *Client) QueryDecisionWithFilter(filter map[string][]string) ([]*ent.Decision, error) {
	var data []*ent.Decision
	var err error

	decisions := c.Ent.Debug().Decision.Query().
		Where(decision.UntilGTE(time.Now()))

	decisions, err = BuildDecisionRequestWithFilter(decisions, filter)
	if err != nil {
		return []*ent.Decision{}, err
	}

	err = decisions.Select(
		decision.FieldUntil,
		decision.FieldScenario,
		decision.FieldType,
		decision.FieldStartIP,
		decision.FieldEndIP,
		decision.FieldTarget,
		decision.FieldScope,
	).Scan(c.CTX, &data)
	if err != nil {
		return []*ent.Decision{}, errors.Wrap(QueryFail, "creating decision failed")
	}

	return data, nil
}

func (c *Client) QueryAllDecisions() ([]*ent.Decision, error) {
	data, err := c.Ent.Debug().Decision.Query().All(c.CTX)
	if err != nil {
		return []*ent.Decision{}, errors.Wrap(QueryFail, "get all decisions")
	}
	return data, nil
}

func (c *Client) QueryExpiredDecisions() ([]*ent.Decision, error) {
	data, err := c.Ent.Debug().Decision.Query().Where(decision.UntilLT(time.Now())).All(c.CTX)
	if err != nil {
		return []*ent.Decision{}, errors.Wrap(QueryFail, "expired decisions")
	}
	return data, nil
}

func (c *Client) QueryNewDecisionsSince(since time.Time) ([]*ent.Decision, error) {
	data, err := c.Ent.Debug().Decision.Query().Where(decision.CreatedAtGT(since)).All(c.CTX)
	if err != nil {
		return []*ent.Decision{}, errors.Wrap(QueryFail, fmt.Sprintf("new decisions since '%s'", since.String()))
	}

	return data, nil
}

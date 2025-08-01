package censeye

import (
	"github.com/censys-research/censeye-ng/pkg/config"
	"github.com/censys/censys-sdk-go/models/components"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// CompileRules is a public helper function that takes an input host result, and generates a list of rules
// with the default configuration. This is for use in external applications who want to manually query the
// endpoints without using the Censeye client directly.
func CompileRules(input []byte) components.SearchValueCountsInputBody {
	var inputResult gjson.Result
	if len(input) > 0 {
		inputResult = gjson.ParseBytes(input)
	} else {
		inputResult = gjson.Result{}
	}

	c := &Censeye{
		config: config.NewConfig(),
	}

	rules, err := c.compileRules(inputResult)
	if err != nil {
		log.Warnf("error compiling rules: %v", err)
		return components.SearchValueCountsInputBody{}
	}

	srules := components.SearchValueCountsInputBody{
		AndCountConditions: make([]components.CountCondition, 0),
	}

	for _, rule := range rules {
		srule := components.CountCondition{
			FieldValuePairs: rule,
		}
		srules.AndCountConditions = append(srules.AndCountConditions, srule)
	}

	return srules
}

// logForHost is a private helper function that returns a log entry with the host field set.
func logForHost(host string) *log.Entry { return log.WithField("host", host) }

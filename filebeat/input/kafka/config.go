// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package kafka

import (
	"errors"
	"fmt"
	"time"

	"github.com/Shopify/sarama"

	"github.com/elastic/beats/libbeat/common/kafka"
	"github.com/elastic/beats/libbeat/common/transport/tlscommon"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/monitoring"
	"github.com/elastic/beats/libbeat/monitoring/adapter"
	"github.com/elastic/beats/libbeat/outputs"
)

type kafkaInputConfig struct {
	// Kafka hosts with port, e.g. "localhost:9092"
	Hosts []string `config:"hosts" validate:"required"`
	// Topics is required for both the consumer-group and direct-read modes.
	Topics []string `config:"topics" validate:"required"`
	// GroupID is optional at unpack time so direct_read can omit it. Validate
	// requires it for the consumer-group mode and rejects it for direct_read.
	// A pointer keeps "not configured" distinguishable from an explicit empty
	// string, which must also be rejected in direct_read mode.
	GroupID                  *string           `config:"group_id"`
	ClientID                 string            `config:"client_id"`
	Version                  kafka.Version     `config:"version"`
	InitialOffset            initialOffset     `config:"initial_offset"`
	ConnectBackoff           time.Duration     `config:"connect_backoff" validate:"min=0"`
	ConsumeBackoff           time.Duration     `config:"consume_backoff" validate:"min=0"`
	WaitClose                time.Duration     `config:"wait_close" validate:"min=0"`
	MaxWaitTime              time.Duration     `config:"max_wait_time"`
	IsolationLevel           isolationLevel    `config:"isolation_level"`
	Fetch                    kafkaFetch        `config:"fetch"`
	Rebalance                kafkaRebalance    `config:"rebalance"`
	TLS                      *tlscommon.Config `config:"ssl"`
	Username                 string            `config:"username"`
	Password                 string            `config:"password"`
	Mechanism                string            `config:"sasl_mechanism"`
	ExpandEventListFromField string            `config:"expand_event_list_from_field"`
	DirectRead               *directReadConfig `config:"direct_read"`
}

// directReadConfig selects the finite, consumer-group-less preview read mode.
// max_events and timeout use pointers so "the field was provided" can be
// distinguished from the zero value while still rejecting zero explicitly.
type directReadConfig struct {
	Enabled   bool           `config:"enabled"`
	MaxEvents *int           `config:"max_events"`
	Timeout   *time.Duration `config:"timeout"`
}

const (
	directReadMinEvents  = 1
	directReadMaxEvents  = 1000
	directReadMinTimeout = time.Second
	directReadMaxTimeout = 60 * time.Second
)

func (d *directReadConfig) validate() error {
	if d == nil {
		return nil
	}
	if !d.Enabled {
		if d.MaxEvents != nil || d.Timeout != nil {
			return errors.New("direct_read.max_events and direct_read.timeout require direct_read.enabled: true")
		}
		return nil
	}
	if d.MaxEvents == nil {
		return errors.New("direct_read.max_events is required when direct_read.enabled is true")
	}
	if d.Timeout == nil {
		return errors.New("direct_read.timeout is required when direct_read.enabled is true")
	}
	if *d.MaxEvents < directReadMinEvents || *d.MaxEvents > directReadMaxEvents {
		return fmt.Errorf("direct_read.max_events must be between %d and %d", directReadMinEvents, directReadMaxEvents)
	}
	if *d.Timeout < directReadMinTimeout || *d.Timeout > directReadMaxTimeout {
		return fmt.Errorf("direct_read.timeout must be between %s and %s", directReadMinTimeout, directReadMaxTimeout)
	}
	return nil
}

type kafkaFetch struct {
	Min     int32 `config:"min" validate:"min=1"`
	Default int32 `config:"default" validate:"min=1"`
	Max     int32 `config:"max" validate:"min=0"`
}

type kafkaRebalance struct {
	Strategy     rebalanceStrategy `config:"strategy"`
	Timeout      time.Duration     `config:"timeout"`
	MaxRetries   int               `config:"max_retries"`
	RetryBackoff time.Duration     `config:"retry_backoff" validate:"min=0"`
}

type initialOffset int

const (
	initialOffsetOldest initialOffset = iota
	initialOffsetNewest
)

type rebalanceStrategy int

const (
	rebalanceStrategyRange rebalanceStrategy = iota
	rebalanceStrategyRoundRobin
)

type isolationLevel int

const (
	isolationLevelReadUncommitted = iota
	isolationLevelReadCommitted
)

var (
	initialOffsets = map[string]initialOffset{
		"oldest": initialOffsetOldest,
		"newest": initialOffsetNewest,
	}
	rebalanceStrategies = map[string]rebalanceStrategy{
		"range":      rebalanceStrategyRange,
		"roundrobin": rebalanceStrategyRoundRobin,
	}
	isolationLevels = map[string]isolationLevel{
		"read_uncommitted": isolationLevelReadUncommitted,
		"read_committed":   isolationLevelReadCommitted,
	}
)

// The default config for the kafka input. When in doubt, default values
// were chosen to match sarama's defaults.
func defaultConfig() kafkaInputConfig {
	return kafkaInputConfig{
		Version:        kafka.Version("1.0.0"),
		InitialOffset:  initialOffsetNewest,
		ClientID:       "filebeat",
		ConnectBackoff: 30 * time.Second,
		ConsumeBackoff: 2 * time.Second,
		WaitClose:      2 * time.Second,
		MaxWaitTime:    250 * time.Millisecond,
		IsolationLevel: isolationLevelReadUncommitted,
		Fetch: kafkaFetch{
			Min:     1,
			Default: (1 << 20), // 1 MB
			Max:     0,
		},
		Rebalance: kafkaRebalance{
			Strategy:     rebalanceStrategyRange,
			Timeout:      60 * time.Second,
			MaxRetries:   4,
			RetryBackoff: 2 * time.Second,
		},
	}
}

// Validate validates the config.
func (c *kafkaInputConfig) Validate() error {
	if len(c.Hosts) == 0 {
		return errors.New("no hosts configured")
	}
	if len(c.Topics) == 0 {
		return errors.New("no topics configured")
	}

	if err := c.Version.Validate(); err != nil {
		return err
	}

	if c.Username != "" && c.Password == "" {
		return fmt.Errorf("password must be set when username is configured")
	}

	if _, err := kafka.NormalizeSASLMechanism(c.Mechanism); err != nil {
		return err
	}

	// Validate the direct-read block before group_id. A disabled block that
	// still carries limits is a config error even when group_id is also missing.
	if err := c.DirectRead.validate(); err != nil {
		return err
	}

	direct := c.DirectRead != nil && c.DirectRead.Enabled
	if direct {
		// A direct preview must never join or create a consumer group. An
		// explicit empty group_id is still "configured" and is rejected too.
		if c.GroupID != nil {
			return errors.New("group_id must not be set when direct_read.enabled is true")
		}
	} else if c.GroupID == nil || *c.GroupID == "" {
		return errors.New("group_id is required when direct_read is disabled")
	}

	return nil
}

func newSaramaConfig(config kafkaInputConfig) (*sarama.Config, error) {
	k := sarama.NewConfig()

	version, ok := config.Version.Get()
	if !ok {
		return nil, fmt.Errorf("Unknown/unsupported kafka version: %v", config.Version)
	}
	k.Version = version

	k.Consumer.Return.Errors = true
	k.Consumer.Offsets.Initial = config.InitialOffset.asSaramaOffset()
	k.Consumer.Retry.Backoff = config.ConsumeBackoff
	k.Consumer.MaxWaitTime = config.MaxWaitTime
	k.Consumer.IsolationLevel = config.IsolationLevel.asSaramaIsolationLevel()

	k.Consumer.Fetch.Min = config.Fetch.Min
	k.Consumer.Fetch.Default = config.Fetch.Default
	k.Consumer.Fetch.Max = config.Fetch.Max

	k.Consumer.Group.Rebalance.Strategy =
		config.Rebalance.Strategy.asSaramaStrategy()
	k.Consumer.Group.Rebalance.Timeout = config.Rebalance.Timeout
	k.Consumer.Group.Rebalance.Retry.Backoff = config.Rebalance.RetryBackoff
	k.Consumer.Group.Rebalance.Retry.Max = config.Rebalance.MaxRetries

	tls, err := outputs.LoadTLSConfig(config.TLS)
	if err != nil {
		return nil, err
	}
	if tls != nil {
		k.Net.TLS.Enable = true
		k.Net.TLS.Config = tls.BuildModuleConfig("")
	}

	if err := kafka.ConfigureSASL(k, config.Username, config.Password, config.Mechanism); err != nil {
		return nil, err
	}

	// configure client ID
	k.ClientID = config.ClientID

	k.MetricRegistry = adapter.GetGoMetrics(
		monitoring.Default,
		"filebeat.inputs.kafka",
		adapter.Rename("incoming-byte-rate", "bytes_read"),
		adapter.Rename("outgoing-byte-rate", "bytes_write"),
		adapter.GoMetricsNilify,
	)

	if err := k.Validate(); err != nil {
		logp.Err("Invalid kafka configuration: %v", err)
		return nil, err
	}
	return k, nil
}

// asSaramaOffset converts an initialOffset enum to the corresponding
// sarama offset value.
func (off initialOffset) asSaramaOffset() int64 {
	return map[initialOffset]int64{
		initialOffsetOldest: sarama.OffsetOldest,
		initialOffsetNewest: sarama.OffsetNewest,
	}[off]
}

// Unpack validates and unpack the "initial_offset" config option
func (off *initialOffset) Unpack(value string) error {
	initialOffset, ok := initialOffsets[value]
	if !ok {
		return fmt.Errorf("invalid initialOffset '%s'", value)
	}
	*off = initialOffset
	return nil
}

func (st rebalanceStrategy) asSaramaStrategy() sarama.BalanceStrategy {
	return map[rebalanceStrategy]sarama.BalanceStrategy{
		rebalanceStrategyRange:      sarama.BalanceStrategyRange,
		rebalanceStrategyRoundRobin: sarama.BalanceStrategyRoundRobin,
	}[st]
}

// Unpack validates and unpack the "rebalance.strategy" config option
func (st *rebalanceStrategy) Unpack(value string) error {
	strategy, ok := rebalanceStrategies[value]
	if !ok {
		return fmt.Errorf("invalid rebalance strategy '%s'", value)
	}
	*st = strategy
	return nil
}

func (is isolationLevel) asSaramaIsolationLevel() sarama.IsolationLevel {
	return map[isolationLevel]sarama.IsolationLevel{
		isolationLevelReadUncommitted: sarama.ReadUncommitted,
		isolationLevelReadCommitted:   sarama.ReadCommitted,
	}[is]
}

func (is *isolationLevel) Unpack(value string) error {
	isolationLevel, ok := isolationLevels[value]
	if !ok {
		return fmt.Errorf("invalid isolation level '%s'", value)
	}
	*is = isolationLevel
	return nil
}

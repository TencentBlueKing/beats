// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package kafka

import (
	"testing"
	"time"

	"github.com/Shopify/sarama"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/libbeat/common"
)

func TestSASLMechanismConfig(t *testing.T) {
	base := common.MapStr{
		"hosts":    []string{"localhost:9092"},
		"topics":   []string{"test"},
		"group_id": "test-group",
	}
	tests := map[string]struct {
		config    common.MapStr
		mechanism sarama.SASLMechanism
		scram     bool
		wantErr   bool
	}{
		"no sasl config": {
			config:    common.MapStr{},
			mechanism: "",
		},
		"plain by default when username set": {
			config: common.MapStr{
				"username": "user",
				"password": "pass",
			},
			mechanism: sarama.SASLTypePlaintext,
		},
		"explicit plain": {
			config: common.MapStr{
				"username":       "user",
				"password":       "pass",
				"sasl_mechanism": "PLAIN",
			},
			mechanism: sarama.SASLTypePlaintext,
		},
		"scram sha 512": {
			config: common.MapStr{
				"username":       "user",
				"password":       "pass",
				"sasl_mechanism": "SCRAM-SHA-512",
			},
			mechanism: sarama.SASLTypeSCRAMSHA512,
			scram:     true,
		},
		"scram sha 256 lowercase": {
			config: common.MapStr{
				"username":       "user",
				"password":       "pass",
				"sasl_mechanism": "scram-sha-256",
			},
			mechanism: sarama.SASLTypeSCRAMSHA256,
			scram:     true,
		},
		"unsupported mechanism": {
			config: common.MapStr{
				"username":       "user",
				"password":       "pass",
				"sasl_mechanism": "GSSAPI",
			},
			wantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfgMap := common.MapStr{}
			for k, v := range base {
				cfgMap[k] = v
			}
			for k, v := range test.config {
				cfgMap[k] = v
			}

			config := defaultConfig()
			err := common.MustNewConfigFrom(cfgMap).Unpack(&config)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			k, err := newSaramaConfig(config)
			require.NoError(t, err)
			assert.Equal(t, test.mechanism, k.Net.SASL.Mechanism)
			if test.scram {
				assert.NotNil(t, k.Net.SASL.SCRAMClientGeneratorFunc)
			} else {
				assert.Nil(t, k.Net.SASL.SCRAMClientGeneratorFunc)
			}
		})
	}
}

func kafkaConfigMap() common.MapStr {
	return common.MapStr{
		"hosts":    []string{"localhost:9092"},
		"topics":   []string{"test"},
		"group_id": "test-group",
	}
}

func directReadConfigMap() common.MapStr {
	cfg := kafkaConfigMap()
	delete(cfg, "group_id")
	cfg["direct_read"] = common.MapStr{
		"enabled":    true,
		"max_events": 30,
		"timeout":    "10s",
	}
	return cfg
}

func TestKafkaInputConfigValidation(t *testing.T) {
	tests := map[string]struct {
		config  common.MapStr
		wantErr string
	}{
		"consumer group minimal": {
			config: kafkaConfigMap(),
		},
		"consumer group missing group_id": {
			config: func() common.MapStr {
				cfg := kafkaConfigMap()
				delete(cfg, "group_id")
				return cfg
			}(),
			wantErr: "group_id is required",
		},
		"consumer group empty group_id": {
			config: func() common.MapStr {
				cfg := kafkaConfigMap()
				cfg["group_id"] = ""
				return cfg
			}(),
			wantErr: "group_id is required",
		},
		"direct read minimal": {
			config: directReadConfigMap(),
		},
		"direct read with group_id": {
			config: func() common.MapStr {
				cfg := directReadConfigMap()
				cfg["group_id"] = "test-group"
				return cfg
			}(),
			wantErr: "group_id must not be set",
		},
		"direct read with empty group_id": {
			config: func() common.MapStr {
				cfg := directReadConfigMap()
				cfg["group_id"] = ""
				return cfg
			}(),
			wantErr: "group_id must not be set",
		},
		"direct read missing max_events": {
			config: func() common.MapStr {
				cfg := directReadConfigMap()
				delete(cfg["direct_read"].(common.MapStr), "max_events")
				return cfg
			}(),
			wantErr: "direct_read.max_events is required",
		},
		"direct read missing timeout": {
			config: func() common.MapStr {
				cfg := directReadConfigMap()
				delete(cfg["direct_read"].(common.MapStr), "timeout")
				return cfg
			}(),
			wantErr: "direct_read.timeout is required",
		},
		"direct read zero max_events": {
			config: func() common.MapStr {
				cfg := directReadConfigMap()
				cfg["direct_read"].(common.MapStr)["max_events"] = 0
				return cfg
			}(),
			wantErr: "direct_read.max_events must be between",
		},
		"direct read too many max_events": {
			config: func() common.MapStr {
				cfg := directReadConfigMap()
				cfg["direct_read"].(common.MapStr)["max_events"] = 1001
				return cfg
			}(),
			wantErr: "direct_read.max_events must be between",
		},
		"direct read too short timeout": {
			config: func() common.MapStr {
				cfg := directReadConfigMap()
				cfg["direct_read"].(common.MapStr)["timeout"] = "999ms"
				return cfg
			}(),
			wantErr: "direct_read.timeout must be between",
		},
		"direct read too long timeout": {
			config: func() common.MapStr {
				cfg := directReadConfigMap()
				cfg["direct_read"].(common.MapStr)["timeout"] = "61s"
				return cfg
			}(),
			wantErr: "direct_read.timeout must be between",
		},
		"disabled direct read with max_events": {
			config: func() common.MapStr {
				cfg := kafkaConfigMap()
				cfg["direct_read"] = common.MapStr{
					"enabled":    false,
					"max_events": 30,
				}
				return cfg
			}(),
			wantErr: "require direct_read.enabled",
		},
		"disabled direct read with timeout": {
			config: func() common.MapStr {
				cfg := kafkaConfigMap()
				cfg["direct_read"] = common.MapStr{
					"enabled": false,
					"timeout": "10s",
				}
				return cfg
			}(),
			wantErr: "require direct_read.enabled",
		},
		"disabled direct read with max_events and missing group_id": {
			config: func() common.MapStr {
				cfg := kafkaConfigMap()
				delete(cfg, "group_id")
				cfg["direct_read"] = common.MapStr{
					"enabled":    false,
					"max_events": 30,
				}
				return cfg
			}(),
			wantErr: "require direct_read.enabled",
		},
		"empty topics": {
			config: func() common.MapStr {
				cfg := kafkaConfigMap()
				cfg["topics"] = []string{}
				return cfg
			}(),
			wantErr: "empty field accessing 'topics'",
		},
		"missing hosts": {
			config: func() common.MapStr {
				cfg := kafkaConfigMap()
				delete(cfg, "hosts")
				return cfg
			}(),
			wantErr: "missing required field accessing 'hosts'",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := defaultConfig()
			err := common.MustNewConfigFrom(test.config).Unpack(&config)
			if test.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestKafkaInputValidateEmptyTopics(t *testing.T) {
	config := defaultConfig()
	config.Hosts = []string{"kafka:9092"}
	config.Topics = nil
	groupID := "group"
	config.GroupID = &groupID

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no topics configured")
}

func TestKafkaInputDirectReadConfig(t *testing.T) {
	config := defaultConfig()
	require.NoError(t, common.MustNewConfigFrom(directReadConfigMap()).Unpack(&config))

	require.Nil(t, config.GroupID)
	require.NotNil(t, config.DirectRead)
	assert.True(t, config.DirectRead.Enabled)
	require.NotNil(t, config.DirectRead.MaxEvents)
	require.NotNil(t, config.DirectRead.Timeout)
	assert.Equal(t, 30, *config.DirectRead.MaxEvents)
	assert.Equal(t, 10*time.Second, *config.DirectRead.Timeout)

	// Boundaries are accepted by the collector guard rails.
	for _, tc := range []struct {
		name    string
		events  int
		timeout string
	}{
		{name: "lower bounds", events: 1, timeout: "1s"},
		{name: "upper bounds", events: 1000, timeout: "60s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgMap := directReadConfigMap()
			cfgMap["direct_read"].(common.MapStr)["max_events"] = tc.events
			cfgMap["direct_read"].(common.MapStr)["timeout"] = tc.timeout

			cfg := defaultConfig()
			require.NoError(t, common.MustNewConfigFrom(cfgMap).Unpack(&cfg))
			assert.Equal(t, tc.events, *cfg.DirectRead.MaxEvents)
		})
	}
}

func TestKafkaInputGroupIDPointer(t *testing.T) {
	// An explicitly empty group_id is not the same as an absent one. The
	// consumer-group path must reject it and direct_read must reject both.
	config := defaultConfig()
	require.NoError(t, common.MustNewConfigFrom(kafkaConfigMap()).Unpack(&config))
	require.NotNil(t, config.GroupID)
	assert.Equal(t, "test-group", *config.GroupID)

	cfgMap := kafkaConfigMap()
	cfgMap["group_id"] = ""
	config = defaultConfig()
	err := common.MustNewConfigFrom(cfgMap).Unpack(&config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group_id is required")
}

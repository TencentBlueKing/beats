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
	"sync"
	"testing"
	"time"

	"github.com/Shopify/sarama"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/filebeat/channel"
	filebeatinput "github.com/elastic/beats/filebeat/input"
	"github.com/elastic/beats/filebeat/util"
	"github.com/elastic/beats/libbeat/logp"
)

type fakePartitionConsumer struct {
	messages chan *sarama.ConsumerMessage
	errors   chan *sarama.ConsumerError

	closeOnce sync.Once
	closed    chan struct{}
}

func newFakePartitionConsumer() *fakePartitionConsumer {
	return &fakePartitionConsumer{
		messages: make(chan *sarama.ConsumerMessage, 64),
		errors:   make(chan *sarama.ConsumerError, 8),
		closed:   make(chan struct{}),
	}
}

func (p *fakePartitionConsumer) AsyncClose() {
	p.closeOnce.Do(func() {
		close(p.closed)
		close(p.messages)
		close(p.errors)
	})
}

func (p *fakePartitionConsumer) Close() error {
	p.AsyncClose()
	return nil
}

func (p *fakePartitionConsumer) Messages() <-chan *sarama.ConsumerMessage {
	return p.messages
}

func (p *fakePartitionConsumer) Errors() <-chan *sarama.ConsumerError {
	return p.errors
}

func (p *fakePartitionConsumer) HighWaterMarkOffset() int64 { return 0 }

type fakeDirectConsumer struct {
	topics     map[string][]int32
	partitions map[string]*fakePartitionConsumer

	partitionsErr error

	mu        sync.Mutex
	offsets   []int64
	consumed  int
	closeCall int
	closeErr  error
}

func newFakeDirectConsumer() *fakeDirectConsumer {
	return &fakeDirectConsumer{
		topics:     map[string][]int32{},
		partitions: map[string]*fakePartitionConsumer{},
	}
}

func (c *fakeDirectConsumer) Partitions(topic string) ([]int32, error) {
	if c.partitionsErr != nil {
		return nil, c.partitionsErr
	}
	partitions, ok := c.topics[topic]
	if !ok {
		return nil, fmt.Errorf("unknown topic %q", topic)
	}
	return append([]int32(nil), partitions...), nil
}

func (c *fakeDirectConsumer) ConsumePartition(topic string, partition int32, offset int64) (sarama.PartitionConsumer, error) {
	key := fmt.Sprintf("%s/%d", topic, partition)
	c.mu.Lock()
	defer c.mu.Unlock()
	pc, ok := c.partitions[key]
	if !ok || pc == nil {
		pc = newFakePartitionConsumer()
		c.partitions[key] = pc
	}
	c.offsets = append(c.offsets, offset)
	c.consumed++
	return pc, nil
}

func (c *fakeDirectConsumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeCall++
	return c.closeErr
}

func (c *fakeDirectConsumer) addMessages(topic string, partition int32, values ...string) {
	c.mu.Lock()
	pc := c.partitions[fmt.Sprintf("%s/%d", topic, partition)]
	c.mu.Unlock()
	if pc == nil {
		panic("partition consumer not created")
	}
	for i, value := range values {
		pc.messages <- &sarama.ConsumerMessage{
			Topic:     topic,
			Partition: partition,
			Offset:    int64(i),
			Value:     []byte(value),
		}
	}
}

type fakeOutlet struct {
	mu       sync.Mutex
	events   []*util.Data
	rejectAt int
}

func (o *fakeOutlet) OnEvent(data *util.Data) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.rejectAt > 0 && len(o.events) >= o.rejectAt {
		return false
	}
	o.events = append(o.events, data)
	return true
}

func (o *fakeOutlet) Close() error { return nil }
func (o *fakeOutlet) Done() <-chan struct{} {
	return nil
}

func (o *fakeOutlet) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.events)
}

func newDirectTestInput(
	t *testing.T,
	cfg kafkaInputConfig,
	outlet channel.Outleter,
	factory directConsumerFactory,
) *kafkaInput {
	t.Helper()
	saramaConfig, err := newSaramaConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, cfg.DirectRead)
	return &kafkaInput{
		config:                cfg,
		saramaConfig:          saramaConfig,
		context:               filebeatinput.Context{Done: make(chan struct{})},
		outlet:                outlet,
		log:                   logp.NewLogger("kafka direct test"),
		completion:            make(chan struct{}),
		directConsumerFactory: factory,
	}
}

func directConfig(maxEvents int, timeout time.Duration) *directReadConfig {
	return &directReadConfig{
		Enabled:   true,
		MaxEvents: &maxEvents,
		Timeout:   &timeout,
	}
}

func directTestConfig(maxEvents int, timeout time.Duration) kafkaInputConfig {
	cfg := defaultConfig()
	cfg.Hosts = []string{"kafka:9092"}
	cfg.Topics = []string{"test-topic"}
	cfg.GroupID = nil
	cfg.DirectRead = directConfig(maxEvents, timeout)
	return cfg
}

func runDirectToCompletion(t *testing.T, input *kafkaInput) error {
	t.Helper()
	input.Run()
	select {
	case <-input.completion:
		return input.CompletionErr()
	case <-time.After(5 * time.Second):
		t.Fatal("direct read did not complete in time")
		return nil
	}
}

func TestDirectReadMaxEventsAcrossPartitions(t *testing.T) {
	cfg := directTestConfig(5, time.Second)
	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0, 1}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()
	consumer.partitions["test-topic/1"] = newFakePartitionConsumer()

	outlet := &fakeOutlet{}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		assert.Equal(t, directChannelBufferSize, conf.ChannelBufferSize)
		assert.Equal(t, int32(directFetchMaxBytes), conf.Consumer.Fetch.Max)
		assert.Equal(t, 200*time.Millisecond, conf.Consumer.MaxWaitTime)
		assert.Equal(t, time.Second, conf.Net.DialTimeout)
		assert.Equal(t, 1, conf.Metadata.Retry.Max)
		return consumer, nil
	})

	for _, partition := range []int32{0, 1} {
		for i := 0; i < 10; i++ {
			consumer.addMessages("test-topic", partition, fmt.Sprintf("p%d-%d", partition, i))
		}
	}

	require.NoError(t, runDirectToCompletion(t, input))
	assert.Equal(t, 5, outlet.count(), "direct read must stop at max_events, not per partition")

	consumer.mu.Lock()
	closeCalls := consumer.closeCall
	consumer.mu.Unlock()
	assert.Equal(t, 1, closeCalls, "consumer must be closed exactly once")
}

func TestDirectReadExpandedMessageRespectsBudget(t *testing.T) {
	cfg := directTestConfig(3, time.Second)
	cfg.ExpandEventListFromField = "records"

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()

	outlet := &fakeOutlet{}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})

	consumer.addMessages("test-topic", 0, `{"records":[1,2,3,4,5]}`)

	require.NoError(t, runDirectToCompletion(t, input))
	assert.Equal(t, 3, outlet.count(), "one message expanding to many events must not exceed max_events")
}

func TestDirectReadEmptyTopicTimesOutSuccessfully(t *testing.T) {
	cfg := directTestConfig(10, 50*time.Millisecond)

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()

	outlet := &fakeOutlet{}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})

	require.NoError(t, runDirectToCompletion(t, input))
	assert.Equal(t, 0, outlet.count())
}

func TestDirectReadConnectFailure(t *testing.T) {
	cfg := directTestConfig(1, time.Second)
	cfg.ConnectBackoff = 10 * time.Millisecond

	outlet := &fakeOutlet{}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return nil, errors.New("broker unreachable")
	})

	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connecting to kafka")
	assert.Contains(t, err.Error(), "broker unreachable")
}

func TestDirectReadDeadlineDuringConnect(t *testing.T) {
	cfg := directTestConfig(1, 20*time.Millisecond)
	cfg.ConnectBackoff = 10 * time.Millisecond

	outlet := &fakeOutlet{}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		time.Sleep(30 * time.Millisecond)
		return nil, errors.New("slow failure")
	})

	start := time.Now()
	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out before connecting")
	assert.Less(t, time.Since(start), time.Second)
}

func TestDirectReadPartitionLimit(t *testing.T) {
	cfg := directTestConfig(1, time.Second)

	consumer := newFakeDirectConsumer()
	partitions := make([]int32, directMaxPartitions+1)
	for i := range partitions {
		partitions[i] = int32(i)
	}
	consumer.topics["test-topic"] = partitions

	outlet := &fakeOutlet{}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})

	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceed the limit")
	assert.Equal(t, 1, consumer.closeCall)
}

func TestDirectReadOversizeMessageFails(t *testing.T) {
	cfg := directTestConfig(1, time.Second)

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()

	outlet := &fakeOutlet{}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})

	consumer.mu.Lock()
	pc := consumer.partitions["test-topic/0"]
	consumer.mu.Unlock()
	pc.messages <- &sarama.ConsumerMessage{
		Topic:     "test-topic",
		Partition: 0,
		Value:     make([]byte, directMaxMessageBytes+1),
	}

	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "limit is")
	assert.Equal(t, 0, outlet.count())
}

func TestDirectReadOutletRejectionFails(t *testing.T) {
	cfg := directTestConfig(10, time.Second)

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()

	outlet := &fakeOutlet{rejectAt: 1}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})
	consumer.addMessages("test-topic", 0, "one", "two")

	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outlet rejected")
}

func TestDirectReadExternalCancellationFails(t *testing.T) {
	cfg := directTestConfig(10, 5*time.Second)

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()

	connected := make(chan struct{})
	outlet := &fakeOutlet{}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		close(connected)
		return consumer, nil
	})

	input.Run()
	<-connected
	close(input.context.Done)

	select {
	case <-input.completion:
		require.Error(t, input.CompletionErr())
		assert.Contains(t, input.CompletionErr().Error(), "canceled")
	case <-time.After(5 * time.Second):
		t.Fatal("direct read did not complete after cancellation")
	}
}

func TestDirectReadOffsetAndCompletionOnce(t *testing.T) {
	cfg := directTestConfig(1, time.Second)
	cfg.InitialOffset = initialOffsetOldest

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()

	outlet := &fakeOutlet{}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})
	consumer.addMessages("test-topic", 0, "oldest")

	require.NoError(t, runDirectToCompletion(t, input))
	consumer.mu.Lock()
	offsets := append([]int64(nil), consumer.offsets...)
	consumer.mu.Unlock()
	require.Equal(t, []int64{sarama.OffsetOldest}, offsets)

	// Completion is closed once even if the input is started again.
	input.Run()
	input.complete(nil)
	assert.Equal(t, 1, outlet.count())
}

func TestCompletionUnsupportedForConsumerGroup(t *testing.T) {
	cfg := defaultConfig()
	cfg.Hosts = []string{"kafka:9092"}
	cfg.Topics = []string{"test-topic"}
	groupID := "group"
	cfg.GroupID = &groupID

	input := &kafkaInput{config: cfg, completion: make(chan struct{})}
	completion, ok := input.Completion()
	assert.False(t, ok)
	assert.Nil(t, completion)
}

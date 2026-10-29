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
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Shopify/sarama"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/filebeat/channel"
	filebeatinput "github.com/elastic/beats/filebeat/input"
	"github.com/elastic/beats/filebeat/util"
	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/logp"
)

type fakePartitionConsumer struct {
	messages chan *sarama.ConsumerMessage
	errors   chan *sarama.ConsumerError

	closeOnce      sync.Once
	closed         chan struct{}
	mu             sync.Mutex
	messagesClosed bool
}

func newFakePartitionConsumer() *fakePartitionConsumer {
	return &fakePartitionConsumer{
		messages: make(chan *sarama.ConsumerMessage, 64),
		errors:   make(chan *sarama.ConsumerError, 8),
		closed:   make(chan struct{}),
	}
}

func (p *fakePartitionConsumer) closeMessages() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.messagesClosed {
		return
	}
	p.messagesClosed = true
	close(p.messages)
}

func (p *fakePartitionConsumer) AsyncClose() {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.closeMessages()
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

	mu              sync.Mutex
	offsets         []int64
	consumed        int
	closeCall       int
	closeErr        error
	refreshCalls    int
	topicsCalls     int
	partitionsCalls int
	callSequence    []string
}

func newFakeDirectConsumer() *fakeDirectConsumer {
	return &fakeDirectConsumer{
		topics:     map[string][]int32{},
		partitions: map[string]*fakePartitionConsumer{},
	}
}

// RefreshMetadata and Topics are the stock-API preflight seam: the direct
// branch must refresh the full metadata snapshot and list the known topics
// before it resolves partitions or subscribes.
func (c *fakeDirectConsumer) RefreshMetadata() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshCalls++
	c.callSequence = append(c.callSequence, "refresh_metadata")
	return nil
}

func (c *fakeDirectConsumer) Topics() ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.topicsCalls++
	c.callSequence = append(c.callSequence, "topics")
	topics := make([]string, 0, len(c.topics))
	for topic := range c.topics {
		topics = append(topics, topic)
	}
	sort.Strings(topics)
	return topics, nil
}

func (c *fakeDirectConsumer) Partitions(topic string) ([]int32, error) {
	c.mu.Lock()
	c.partitionsCalls++
	c.callSequence = append(c.callSequence, "partitions:"+topic)
	c.mu.Unlock()
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
	c.callSequence = append(c.callSequence, fmt.Sprintf("consume:%s/%d", topic, partition))
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

// largeExpandedMessage builds a message whose expand_event_list_from_field
// array has elements entries. The payload stays small while the expanded form
// would allocate one event per element.
func largeExpandedMessage(elements int) []byte {
	var builder strings.Builder
	builder.Grow(elements*2 + 16)
	builder.WriteString(`{"records":[`)
	for i := 0; i < elements; i++ {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteByte('0')
	}
	builder.WriteString(`]}`)
	return []byte(builder.String())
}

func TestCreateEventsExpandedListAppliesBudget(t *testing.T) {
	logger := logp.NewLogger("kafka direct test")
	message := &sarama.ConsumerMessage{Value: []byte(`{"records":[1,2,3,4,5]}`)}

	// The consumer-group path passes 0 and keeps expanding every element.
	all := createEvents(defaultConfig().Version, "records", logger, "topic", 0, message, 0)
	require.Len(t, all, 5)

	limited := createEvents(defaultConfig().Version, "records", logger, "topic", 0, message, 2)
	require.Len(t, limited, 2)
}

// TestDirectReadExpandedMessageBudgetBoundsWork is the regression test for the
// max_events=1 large-array report: the direct preview must not serialize and
// materialize every expanded element before applying the remaining budget. The
// array has 200000 elements, so expanding it all would allocate far more than
// the assertion below.
func TestDirectReadExpandedMessageBudgetBoundsWork(t *testing.T) {
	const elements = 200000

	cfg := directTestConfig(1, 2*time.Second)
	cfg.ExpandEventListFromField = "records"

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()

	outlet := &fakeOutlet{}
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})
	consumer.addMessages("test-topic", 0, string(largeExpandedMessage(elements)))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	require.NoError(t, runDirectToCompletion(t, input))
	runtime.ReadMemStats(&after)

	assert.Equal(t, 1, outlet.count())
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("expanding one event from %d elements allocated %d bytes", elements, allocated)
	assert.True(t, allocated < 32<<20,
		"expanding one event from %d elements allocated %d bytes", elements, allocated)
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
	attempts := 0
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		attempts++
		return nil, errors.New("broker unreachable")
	})

	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connecting to kafka")
	assert.Contains(t, err.Error(), "broker unreachable")
	assert.Equal(t, directConnectAttempts, attempts)
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
	assert.True(t, time.Since(start) < time.Second,
		"connect abort took %s, want less than 1s", time.Since(start))
}

type slowSubscribeConsumer struct {
	partitions []int32
	delay      time.Duration

	mu        sync.Mutex
	active    int
	maxActive int
	calls     int
}

func (c *slowSubscribeConsumer) RefreshMetadata() error { return nil }

func (c *slowSubscribeConsumer) Topics() ([]string, error) {
	return []string{"wide-topic"}, nil
}

func (c *slowSubscribeConsumer) Partitions(string) ([]int32, error) {
	return append([]int32(nil), c.partitions...), nil
}

func (c *slowSubscribeConsumer) ConsumePartition(string, int32, int64) (sarama.PartitionConsumer, error) {
	c.mu.Lock()
	c.calls++
	c.active++
	if c.active > c.maxActive {
		c.maxActive = c.active
	}
	c.mu.Unlock()

	time.Sleep(c.delay)

	c.mu.Lock()
	c.active--
	c.mu.Unlock()
	return newFakePartitionConsumer(), nil
}

func (c *slowSubscribeConsumer) Close() error { return nil }

func TestSubscribeDirectSubscribesPartitionsConcurrently(t *testing.T) {
	const partitionCount = 64

	cfg := directTestConfig(1, time.Second)
	cfg.Topics = []string{"wide-topic"}
	input := &kafkaInput{config: cfg}
	consumer := &slowSubscribeConsumer{
		partitions: make([]int32, partitionCount),
		delay:      50 * time.Millisecond,
	}
	for i := range consumer.partitions {
		consumer.partitions[i] = int32(i)
	}

	start := time.Now()
	parts, err := input.subscribeDirect(context.Background(), time.Now().Add(time.Second), consumer)
	elapsed := time.Since(start)

	require.NoError(t, err)
	require.Len(t, parts, partitionCount)
	input.closeDirectPartitions(parts)

	consumer.mu.Lock()
	calls, maxActive := consumer.calls, consumer.maxActive
	consumer.mu.Unlock()
	assert.Equal(t, partitionCount, calls)
	assert.True(t, maxActive <= directSubscribeConcurrency,
		"max concurrent subscriptions = %d, want at most %d", maxActive, directSubscribeConcurrency)
	// Sequential subscription would take 64*50ms = 3.2s. With bounded
	// concurrency (64 workers) the 64 targets run in one batch, well under a
	// second.
	assert.True(t, elapsed < time.Second, "bounded subscription took %s, want less than 1s", elapsed)
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

func TestApplyDirectLimitsClampsFetchDefault(t *testing.T) {
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V1_0_0_0
	cfg.Consumer.Fetch.Default = 8 << 20
	require.NoError(t, applyDirectLimits(cfg, 10*time.Second))
	assert.Equal(t, int32(directFetchMaxBytes), cfg.Consumer.Fetch.Max)
	assert.True(t, cfg.Consumer.Fetch.Default <= cfg.Consumer.Fetch.Max,
		"fetch.default = %d, want at most fetch.max = %d",
		cfg.Consumer.Fetch.Default, cfg.Consumer.Fetch.Max)
}

func TestDirectReadDefaultsToNewest(t *testing.T) {
	cfg := directTestConfig(1, 50*time.Millisecond)
	assert.Equal(t, initialOffsetNewest, cfg.InitialOffset)

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()

	input := newDirectTestInput(t, cfg, &fakeOutlet{}, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})
	require.NoError(t, runDirectToCompletion(t, input))

	consumer.mu.Lock()
	offsets := append([]int64(nil), consumer.offsets...)
	consumer.mu.Unlock()
	require.Equal(t, []int64{sarama.OffsetNewest}, offsets)
}

func TestDirectReadConsumerErrorIsNotTimeoutSuccess(t *testing.T) {
	cfg := directTestConfig(10, 2*time.Second)
	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	pc := newFakePartitionConsumer()
	consumer.partitions["test-topic/0"] = pc
	pc.errors <- &sarama.ConsumerError{
		Topic:     "test-topic",
		Partition: 0,
		Err:       errors.New("offset out of range"),
	}
	// Sarama closes Messages before Errors. Leave Errors open so the reader
	// has to keep selecting after Messages is already closed.
	pc.closeMessages()

	input := newDirectTestInput(t, cfg, &fakeOutlet{}, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})
	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offset out of range")
}

// TestDirectReadBlockedOutletDeliversBeforeCompletion is the regression test
// for the per-event delivery goroutine: when the outlet blocks past the
// deadline, the preview must not close Completion() before OnEvent returns.
// The blocked event is still delivered (the outlet was already inside
// OnEvent), and no event may be delivered after the completion signal.
func TestDirectReadBlockedOutletDeliversBeforeCompletion(t *testing.T) {
	cfg := directTestConfig(10, 80*time.Millisecond)
	outlet := newOrderedBlockingOutlet()

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})
	consumer.addMessages("test-topic", 0, "blocked")

	input.Run()
	select {
	case <-outlet.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the outlet never received an event")
	}
	// Let the preview deadline expire while OnEvent is still blocked. The
	// preview is allowed to wait here: bkunify's abort/StopPublish is the
	// component that releases a blocked outlet.
	time.Sleep(120 * time.Millisecond)
	close(outlet.release)

	select {
	case <-input.completion:
	case <-time.After(2 * time.Second):
		t.Fatal("the preview did not complete after the outlet was released")
	}
	outlet.markCompleted()

	err := input.CompletionErr()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out delivering")

	delivered, late, lastDelivery, completedAt := outlet.snapshot()
	assert.Equal(t, 1, delivered, "the blocked event must still be delivered")
	assert.Equal(t, 0, late, "no event may be delivered after Completion")
	assert.True(t, !lastDelivery.After(completedAt),
		"last delivery %s must not be after completion %s", lastDelivery, completedAt)

	// Give a leftover delivery goroutine the chance to run: the completed
	// preview must not deliver anything else.
	time.Sleep(100 * time.Millisecond)
	delivered, late, _, _ = outlet.snapshot()
	assert.Equal(t, 1, delivered)
	assert.Equal(t, 0, late)
}

// TestDirectReadNoEventsAfterCompletion checks the normal max_events exit:
// Completion() is only closed after the last event was delivered and no event
// follows it.
func TestDirectReadNoEventsAfterCompletion(t *testing.T) {
	cfg := directTestConfig(2, 2*time.Second)
	outlet := &sequenceOutlet{}

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()
	input := newDirectTestInput(t, cfg, outlet, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})
	consumer.addMessages("test-topic", 0, "one", "two", "three", "four")

	require.NoError(t, runDirectToCompletion(t, input))
	outlet.markCompleted()
	time.Sleep(100 * time.Millisecond)

	delivered, late := outlet.snapshot()
	assert.Equal(t, 2, delivered, "the preview must stop at max_events")
	assert.Equal(t, 0, late, "no event may be delivered after Completion")
}

// TestDirectReadMissingTopicFailsBeforePartitions covers the typo and deleted
// topic scenarios: a topic absent from the refreshed metadata must fail with
// an explicit error before any partition or subscription call. Those calls are
// what make stock Sarama send a topic-scoped metadata request, which can
// auto-create the topic on Kafka 1.0+.
func TestDirectReadMissingTopicFailsBeforePartitions(t *testing.T) {
	cfg := directTestConfig(1, time.Second)

	consumer := newFakeDirectConsumer()
	consumer.topics["existing-topic"] = []int32{0}

	input := newDirectTestInput(t, cfg, &fakeOutlet{}, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})

	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `topic "test-topic" does not exist`)

	consumer.mu.Lock()
	refreshCalls, topicsCalls := consumer.refreshCalls, consumer.topicsCalls
	partitionsCalls, consumed := consumer.partitionsCalls, consumer.consumed
	closeCalls := consumer.closeCall
	consumer.mu.Unlock()

	assert.Equal(t, 1, refreshCalls, "the preflight must refresh metadata once")
	assert.Equal(t, 1, topicsCalls, "the preflight must list topics once")
	assert.Equal(t, 0, partitionsCalls, "a missing topic must never reach Partitions")
	assert.Equal(t, 0, consumed, "a missing topic must never be subscribed")
	assert.Equal(t, 1, closeCalls, "the failed preview must still close the consumer")
}

// TestDirectReadPreflightBeforePartitions pins the order of the read-only
// preflight: refresh the full metadata snapshot, list the known topics, then
// resolve partitions and subscribe.
func TestDirectReadPreflightBeforePartitions(t *testing.T) {
	cfg := directTestConfig(10, 50*time.Millisecond)

	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()

	input := newDirectTestInput(t, cfg, &fakeOutlet{}, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})

	require.NoError(t, runDirectToCompletion(t, input))

	consumer.mu.Lock()
	calls := append([]string(nil), consumer.callSequence...)
	consumer.mu.Unlock()
	require.True(t, len(calls) >= 4, "preview made %d calls, want at least 4", len(calls))
	assert.Equal(t, "refresh_metadata", calls[0])
	assert.Equal(t, "topics", calls[1])
	assert.Equal(t, "partitions:test-topic", calls[2])
	assert.Equal(t, "consume:test-topic/0", calls[3])
}

// TestDirectReadAbortReturnsBeforeLateCleanup checks the deadline boundary: the
// caller and Stop() must return at the deadline even though every synchronous
// Sarama call and the consumer close still block. The subscription goroutine
// owns that late cleanup and closes the partition consumers and the consumer
// exactly once afterwards.
func TestDirectReadAbortReturnsBeforeLateCleanup(t *testing.T) {
	const partitions = 4

	cfg := directTestConfig(10, 100*time.Millisecond)
	consumer := newSlowCleanupConsumer(partitions)
	input := newDirectTestInput(t, cfg, &fakeOutlet{}, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})

	input.Run()
	require.True(t, consumer.waitForConsumeStart(2*time.Second),
		"the subscription workers never reached ConsumePartition")

	stopStart := time.Now()
	input.Stop()
	elapsed := time.Since(stopStart)

	err := input.CompletionErr()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out while subscribing")
	assert.True(t, elapsed < time.Second, "Stop took %s, want less than 1s", elapsed)

	// The deadline returned while every ConsumePartition call and the consumer
	// close were still blocked: the cleanup belongs to the subscription
	// goroutine and has not run yet.
	created, started, closeCalls := consumer.snapshot()
	assert.Equal(t, partitions, created)
	assert.Equal(t, partitions, started)
	assert.Equal(t, 0, closeCalls, "late cleanup must not run before the queued calls return")

	close(consumer.releaseConsume)
	require.True(t, consumer.waitForCloseStart(2*time.Second),
		"the late cleanup never closed the consumer")
	close(consumer.releaseClose)
	select {
	case <-consumer.cleanupDone:
	case <-time.After(2 * time.Second):
		t.Fatal("late cleanup did not finish")
	}

	for _, pc := range consumer.partitionConsumers() {
		select {
		case <-pc.closed:
		case <-time.After(time.Second):
			t.Fatal("a late partition consumer was not closed")
		}
	}
	_, _, closeCalls = consumer.snapshot()
	assert.Equal(t, 1, closeCalls, "the late cleanup must close the consumer exactly once")
}

func TestPublishDirectEventSkipsExpiredContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	outlet := &fakeOutlet{}
	input := &kafkaInput{outlet: outlet}
	err := input.publishDirectEvent(ctx, beat.Event{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "canceled while delivering")
	assert.Equal(t, 0, outlet.count())
}

func TestDirectReadPanicCompletes(t *testing.T) {
	cfg := directTestConfig(1, time.Second)
	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()
	input := newDirectTestInput(t, cfg, panicOutlet{}, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		return consumer, nil
	})
	consumer.addMessages("test-topic", 0, "boom")

	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic")
	assert.Contains(t, err.Error(), "outlet panic")
}

func TestDirectReadStopWaitsForCompletion(t *testing.T) {
	cfg := directTestConfig(10, 5*time.Second)
	consumer := newFakeDirectConsumer()
	consumer.topics["test-topic"] = []int32{0}
	consumer.partitions["test-topic/0"] = newFakePartitionConsumer()
	connected := make(chan struct{})
	input := newDirectTestInput(t, cfg, &fakeOutlet{}, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		close(connected)
		return consumer, nil
	})

	input.Run()
	<-connected
	close(input.context.Done)
	input.Stop()

	select {
	case <-input.completion:
	default:
		t.Fatal("Stop returned before the direct read completed")
	}
	require.Error(t, input.CompletionErr())
	assert.Contains(t, input.CompletionErr().Error(), "canceled")
}

type orderedBlockingOutlet struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once

	mu          sync.Mutex
	events      int
	deliveredAt []time.Time
	completed   bool
	completedAt time.Time
	lateEvents  int
}

func newOrderedBlockingOutlet() *orderedBlockingOutlet {
	return &orderedBlockingOutlet{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (o *orderedBlockingOutlet) OnEvent(*util.Data) bool {
	o.once.Do(func() { close(o.started) })
	<-o.release
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.completed {
		o.lateEvents++
	}
	o.events++
	o.deliveredAt = append(o.deliveredAt, time.Now())
	return true
}

func (o *orderedBlockingOutlet) Close() error          { return nil }
func (o *orderedBlockingOutlet) Done() <-chan struct{} { return nil }

func (o *orderedBlockingOutlet) markCompleted() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.completed = true
	o.completedAt = time.Now()
}

func (o *orderedBlockingOutlet) snapshot() (int, int, time.Time, time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var last time.Time
	if len(o.deliveredAt) > 0 {
		last = o.deliveredAt[len(o.deliveredAt)-1]
	}
	return o.events, o.lateEvents, last, o.completedAt
}

type sequenceOutlet struct {
	mu        sync.Mutex
	events    int
	completed bool
	late      int
}

func (o *sequenceOutlet) OnEvent(*util.Data) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.completed {
		o.late++
	}
	o.events++
	return true
}
func (o *sequenceOutlet) Close() error          { return nil }
func (o *sequenceOutlet) Done() <-chan struct{} { return nil }

func (o *sequenceOutlet) markCompleted() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.completed = true
}

func (o *sequenceOutlet) snapshot() (int, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.events, o.late
}

// slowCleanupConsumer is a broker whose synchronous ConsumePartition calls are
// still queued when the preview deadline fires and whose Close is slower than
// the deadline. The test uses it to assert that the caller does not wait for
// either, and that the subscription goroutine closes the late partition
// consumers and the consumer exactly once.
type slowCleanupConsumer struct {
	partitions []int32

	releaseConsume chan struct{}
	consumeStarted chan struct{}
	closeStarted   chan struct{}
	releaseClose   chan struct{}
	cleanupDone    chan struct{}

	consumeOnce sync.Once
	closeOnce   sync.Once
	doneOnce    sync.Once

	mu           sync.Mutex
	created      []*fakePartitionConsumer
	started      int
	refreshCalls int
	topicsCalls  int
	closeCalls   int
}

func newSlowCleanupConsumer(partitionCount int) *slowCleanupConsumer {
	consumer := &slowCleanupConsumer{
		partitions:     make([]int32, partitionCount),
		releaseConsume: make(chan struct{}),
		consumeStarted: make(chan struct{}),
		closeStarted:   make(chan struct{}),
		releaseClose:   make(chan struct{}),
		cleanupDone:    make(chan struct{}),
	}
	for i := range consumer.partitions {
		consumer.partitions[i] = int32(i)
	}
	return consumer
}

func (c *slowCleanupConsumer) RefreshMetadata() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshCalls++
	return nil
}

func (c *slowCleanupConsumer) Topics() ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.topicsCalls++
	return []string{"test-topic"}, nil
}

func (c *slowCleanupConsumer) Partitions(string) ([]int32, error) {
	return append([]int32(nil), c.partitions...), nil
}

func (c *slowCleanupConsumer) ConsumePartition(string, int32, int64) (sarama.PartitionConsumer, error) {
	pc := newFakePartitionConsumer()
	c.mu.Lock()
	c.created = append(c.created, pc)
	c.started++
	c.mu.Unlock()
	c.consumeOnce.Do(func() { close(c.consumeStarted) })
	<-c.releaseConsume
	return pc, nil
}

func (c *slowCleanupConsumer) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	c.closeOnce.Do(func() { close(c.closeStarted) })
	<-c.releaseClose
	c.doneOnce.Do(func() { close(c.cleanupDone) })
	return nil
}

func (c *slowCleanupConsumer) partitionConsumers() []*fakePartitionConsumer {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*fakePartitionConsumer(nil), c.created...)
}

func (c *slowCleanupConsumer) snapshot() (created, started, closeCalls int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.created), c.started, c.closeCalls
}

func (c *slowCleanupConsumer) waitForConsumeStart(timeout time.Duration) bool {
	return waitForCondition(timeout, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.started == len(c.partitions)
	})
}

func (c *slowCleanupConsumer) waitForCloseStart(timeout time.Duration) bool {
	return waitForCondition(timeout, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.closeCalls == 1
	})
}

// waitForCondition polls cond until it is true or the timeout expires.
func waitForCondition(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

type panicOutlet struct{}

func (panicOutlet) OnEvent(*util.Data) bool { panic("outlet panic") }
func (panicOutlet) Close() error            { return nil }
func (panicOutlet) Done() <-chan struct{}   { return nil }

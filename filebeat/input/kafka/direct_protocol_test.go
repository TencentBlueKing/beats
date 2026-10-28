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
	"sync"
	"testing"
	"time"

	"github.com/Shopify/sarama"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/libbeat/common/kafka"
)

// newMetadataMockBroker starts a MockBroker that answers metadata requests
// from response. The direct-read tests use it to assert the exact wire fields
// Sarama sends, which a fake consumer cannot observe.
func newMetadataMockBroker(t *testing.T, response *sarama.MockMetadataResponse) *sarama.MockBroker {
	t.Helper()
	broker := sarama.NewMockBroker(t, 1)
	response.SetBroker(broker.Addr(), broker.BrokerID())
	broker.SetHandlerByMap(map[string]sarama.MockResponse{
		"MetadataRequest": response,
	})
	return broker
}

// TestDirectReadMetadataDisablesTopicAutoCreation is the protocol-level guard
// for the read-only preview guarantee: when the configured topic is missing
// from Sarama's metadata cache, the direct branch refreshes it with a
// topic-scoped MetadataRequest that must not allow topic auto-creation. The
// topic-scoped request is captured from the MockBroker wire history, not from
// a fake consumer.
func TestDirectReadMetadataDisablesTopicAutoCreation(t *testing.T) {
	response := sarama.NewMockMetadataResponse(t).
		SetLeader("existing-topic", 0, 1)
	broker := newMetadataMockBroker(t, response)
	defer broker.Close()

	cfg := directTestConfig(1, 2*time.Second)
	cfg.Hosts = []string{broker.Addr()}
	cfg.Topics = []string{"missing-preview-topic"}

	input := newDirectTestInput(t, cfg, &fakeOutlet{}, nil)
	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	// A missing topic must fail clearly instead of silently returning an empty
	// preview.
	assert.Contains(t, err.Error(), "missing-preview-topic")
	assert.Contains(t, err.Error(), "does not exist")

	topicRequests := 0
	for _, exchange := range broker.History() {
		request, ok := exchange.Request.(*sarama.MetadataRequest)
		if !ok || len(request.Topics) == 0 {
			continue
		}
		topicRequests++
		for _, topic := range request.Topics {
			assert.Equal(t, "missing-preview-topic", topic)
		}
		// Only MetadataRequest v4+ can encode the flag; a lower version would
		// make the decoded false meaningless.
		assert.True(t, request.Version >= 4,
			"metadata request v%d cannot carry the auto-creation flag", request.Version)
		assert.False(t, request.AllowAutoTopicCreation,
			"topic-scoped metadata request %d for %v must not allow auto topic creation",
			topicRequests, request.Topics)
	}
	assert.True(t, topicRequests > 0,
		"the missing topic must be refreshed with a topic-scoped metadata request")
}

// TestDirectReadKafka011UsesMetadataV4 is the Kafka 0.11 counterpart of
// TestDirectReadMetadataDisablesTopicAutoCreation. Sarama selects
// MetadataRequest v5 only for 1.0.0 and newer; for 0.11 its default selection
// would be v1, which does not encode allow_auto_topic_creation at all. The
// direct preview must therefore force v4 on the wire for 0.11, otherwise the
// flag is silently dropped and the broker's auto.create.topics.enable applies.
func TestDirectReadKafka011UsesMetadataV4(t *testing.T) {
	response := sarama.NewMockMetadataResponse(t).
		SetLeader("existing-topic", 0, 1)
	broker := newMetadataMockBroker(t, response)
	defer broker.Close()

	cfg := directTestConfig(1, 2*time.Second)
	cfg.Version = kafka.Version("0.11.0.0")
	cfg.Hosts = []string{broker.Addr()}
	cfg.Topics = []string{"missing-preview-topic"}

	input := newDirectTestInput(t, cfg, &fakeOutlet{}, nil)
	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing-preview-topic")
	assert.Contains(t, err.Error(), "does not exist")

	topicRequests := 0
	fullRequests := 0
	for _, exchange := range broker.History() {
		request, ok := exchange.Request.(*sarama.MetadataRequest)
		if !ok {
			continue
		}
		// Kafka 0.11 supports MetadataRequest v4, the first version that can
		// carry the auto-creation flag. A v1 request would make the decoded
		// false meaningless because the broker never receives it.
		assert.Equal(t, int16(4), request.Version,
			"metadata request for %v must be v4 on kafka 0.11", request.Topics)
		// Every metadata request sent by the preview, including the initial
		// full refresh without topics, must opt out of auto-creation.
		assert.False(t, request.AllowAutoTopicCreation,
			"metadata request for %v must not allow auto topic creation", request.Topics)
		if len(request.Topics) == 0 {
			fullRequests++
			continue
		}
		topicRequests++
		for _, topic := range request.Topics {
			assert.Equal(t, "missing-preview-topic", topic)
		}
	}
	assert.True(t, topicRequests > 0,
		"the missing topic must be refreshed with a topic-scoped metadata request")
	assert.True(t, fullRequests > 0,
		"the client must still perform the initial full metadata refresh")
}

// TestKafka011DefaultMetadataVersionUnchanged guards the other half of the
// vendored version-selection change: a Kafka 0.11 client that keeps the
// default AllowAutoTopicCreation=true must keep sending MetadataRequest v1,
// including its initial full refresh. Only the direct preview opts into v4.
func TestKafka011DefaultMetadataVersionUnchanged(t *testing.T) {
	response := sarama.NewMockMetadataResponse(t).
		SetLeader("existing-topic", 0, 1)
	broker := newMetadataMockBroker(t, response)
	defer broker.Close()

	conf := sarama.NewConfig()
	conf.Version = sarama.V0_11_0_0
	require.True(t, conf.Metadata.AllowAutoTopicCreation,
		"sarama must keep allowing topic auto-creation by default")

	client, err := sarama.NewClient([]string{broker.Addr()}, conf)
	require.NoError(t, err)
	defer client.Close()

	metadataRequests := 0
	for _, exchange := range broker.History() {
		request, ok := exchange.Request.(*sarama.MetadataRequest)
		if !ok {
			continue
		}
		metadataRequests++
		assert.Equal(t, int16(1), request.Version,
			"default kafka 0.11 metadata traffic must stay on v1")
	}
	assert.True(t, metadataRequests > 0,
		"client creation must perform the initial full metadata refresh")
}

// TestDirectAutoTopicCreationConfigDefaults proves the new Sarama option keeps
// the consumer-group path unchanged and only the direct preview opts out.
func TestDirectAutoTopicCreationConfigDefaults(t *testing.T) {
	assert.True(t, sarama.NewConfig().Metadata.AllowAutoTopicCreation,
		"sarama must keep allowing topic auto-creation by default")

	cfg := sarama.NewConfig()
	cfg.Version = sarama.V1_0_0_0
	require.NoError(t, applyDirectLimits(cfg, time.Second))
	assert.False(t, cfg.Metadata.AllowAutoTopicCreation,
		"the direct preview must not allow topic auto-creation")

	groupConfig, err := newSaramaConfig(defaultConfig())
	require.NoError(t, err)
	assert.True(t, groupConfig.Metadata.AllowAutoTopicCreation,
		"the consumer-group path must keep the sarama default")
}

// TestDirectReadRejectsKafkaBefore011 documents the fallback for brokers whose
// MetadataRequest version predates the auto-creation flag: the preview is
// rejected before connecting instead of sending a request that could create a
// topic.
func TestDirectReadRejectsKafkaBefore011(t *testing.T) {
	cfg := directTestConfig(1, time.Second)
	cfg.Version = kafka.Version("0.10.0.0")

	connected := false
	input := newDirectTestInput(t, cfg, &fakeOutlet{}, func(addrs []string, conf *sarama.Config) (directConsumer, error) {
		connected = true
		return newFakeDirectConsumer(), nil
	})

	err := runDirectToCompletion(t, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0.11.0")
	assert.Contains(t, err.Error(), "automatic topic creation")
	assert.False(t, connected, "an unsupported version must be rejected before connecting")
}

func TestApplyDirectLimitsRejectsOldKafkaVersion(t *testing.T) {
	cfg := sarama.NewConfig()
	cfg.Version = sarama.V0_10_2_1

	err := applyDirectLimits(cfg, time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0.11.0")
	assert.Contains(t, err.Error(), "automatic topic creation")
}

// newSlowWideBroker starts a MockBroker serving one topic with partitionCount
// partitions and delays every response by latency. The delayed metadata and
// offset responses make the per-partition subscription calls queue on the
// single broker connection, which is the slow-broker scenario the deadline
// must interrupt.
func newSlowWideBroker(
	t *testing.T,
	topic string,
	partitionCount int,
	latency time.Duration,
) *sarama.MockBroker {
	t.Helper()
	broker := sarama.NewMockBroker(t, 1)
	metadata := sarama.NewMockMetadataResponse(t)
	// Kafka 1.0.0 sends OffsetRequest v1, so the mock response must use it too.
	offsets := sarama.NewMockOffsetResponse(t).SetVersion(1)
	for partition := 0; partition < partitionCount; partition++ {
		id := int32(partition)
		metadata.SetLeader(topic, id, broker.BrokerID())
		// chooseStartingOffset asks for both ends of every partition.
		offsets.SetOffset(topic, id, sarama.OffsetNewest, 0)
		offsets.SetOffset(topic, id, sarama.OffsetOldest, 0)
	}
	metadata.SetBroker(broker.Addr(), broker.BrokerID())
	broker.SetHandlerByMap(map[string]sarama.MockResponse{
		"MetadataRequest": metadata,
		"OffsetRequest":   offsets,
	})
	broker.SetLatency(latency)
	return broker
}

func waitForOffsetRequest(broker *sarama.MockBroker, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, exchange := range broker.History() {
			if _, ok := exchange.Request.(*sarama.OffsetRequest); ok {
				return true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// directConsumerTracker is a test-only seam around the direct consumer factory.
// It records every partition consumer the preview receives from
// ConsumePartition and every shutdown it performs on them, so the cancellation
// test can assert the cleanup contract and not only the completion timing. The
// factory mirrors the production one (a real Sarama client and consumer); only
// the returned consumers are wrapped.
//
// The factory also subscribes to one partition up front and hands that real
// partition consumer to the matching ConsumePartition call. Sarama resolves a
// partition's starting offset with two serialized broker round trips, so with a
// slow mock broker the first worker-created partition consumer can take several
// seconds to appear. The pre-created one makes the cleanup assertion
// deterministic while the remaining subscriptions are still queued when the
// test cancels.
type directConsumerTracker struct {
	mu sync.Mutex

	precreateTopic     string
	precreatePartition int32
	precreated         sarama.PartitionConsumer
	precreatedTaken    bool

	partitionConsumers []*trackedPartitionConsumer
	asyncCloses        int
	closeCalls         int
}

func newDirectConsumerTracker(topic string, partition int32) *directConsumerTracker {
	return &directConsumerTracker{
		precreateTopic:     topic,
		precreatePartition: partition,
	}
}

type trackedDirectConsumer struct {
	directConsumer
	tracker *directConsumerTracker
}

func (t *directConsumerTracker) factory(
	addrs []string,
	conf *sarama.Config,
) (directConsumer, error) {
	client, err := sarama.NewClient(addrs, conf)
	if err != nil {
		return nil, err
	}
	consumer, err := sarama.NewConsumerFromClient(client)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	pc, err := consumer.ConsumePartition(t.precreateTopic, t.precreatePartition, sarama.OffsetNewest)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	t.mu.Lock()
	t.precreated = pc
	t.mu.Unlock()
	return &trackedDirectConsumer{
		directConsumer: &saramaDirectConsumer{client: client, consumer: consumer},
		tracker:        t,
	}, nil
}

func (c *trackedDirectConsumer) ConsumePartition(
	topic string,
	partition int32,
	offset int64,
) (sarama.PartitionConsumer, error) {
	if pc := c.takePrecreated(topic, partition); pc != nil {
		return c.track(topic, partition, pc), nil
	}
	pc, err := c.directConsumer.ConsumePartition(topic, partition, offset)
	if err != nil {
		return nil, err
	}
	return c.track(topic, partition, pc), nil
}

// takePrecreated hands the pre-subscribed partition consumer to its matching
// ConsumePartition call exactly once.
func (c *trackedDirectConsumer) takePrecreated(topic string, partition int32) sarama.PartitionConsumer {
	c.tracker.mu.Lock()
	defer c.tracker.mu.Unlock()
	if c.tracker.precreatedTaken ||
		topic != c.tracker.precreateTopic ||
		partition != c.tracker.precreatePartition {
		return nil
	}
	c.tracker.precreatedTaken = true
	pc := c.tracker.precreated
	c.tracker.precreated = nil
	return pc
}

func (c *trackedDirectConsumer) track(
	topic string,
	partition int32,
	pc sarama.PartitionConsumer,
) sarama.PartitionConsumer {
	tracked := &trackedPartitionConsumer{
		PartitionConsumer: pc,
		tracker:           c.tracker,
		topic:             topic,
		partition:         partition,
	}
	c.tracker.mu.Lock()
	c.tracker.partitionConsumers = append(c.tracker.partitionConsumers, tracked)
	c.tracker.mu.Unlock()
	return tracked
}

func (c *trackedDirectConsumer) Close() error {
	c.tracker.mu.Lock()
	c.tracker.closeCalls++
	pending := c.tracker.precreated
	c.tracker.precreated = nil
	c.tracker.precreatedTaken = true
	c.tracker.mu.Unlock()
	if pending != nil {
		pending.AsyncClose()
	}
	return c.directConsumer.Close()
}

// Abort keeps the deadline/cancel interruption identical to production: the
// direct consumer aborts the broker connections before it is closed.
func (c *trackedDirectConsumer) Abort() {
	if aborter, ok := c.directConsumer.(directConsumerAborter); ok {
		aborter.Abort()
	}
}

type trackedPartitionConsumer struct {
	sarama.PartitionConsumer

	tracker   *directConsumerTracker
	topic     string
	partition int32

	asyncCloseCalls int
}

func (p *trackedPartitionConsumer) AsyncClose() {
	p.tracker.mu.Lock()
	p.asyncCloseCalls++
	p.tracker.asyncCloses++
	p.tracker.mu.Unlock()
	p.PartitionConsumer.AsyncClose()
}

func (p *trackedPartitionConsumer) asyncCloseCount() int {
	p.tracker.mu.Lock()
	defer p.tracker.mu.Unlock()
	return p.asyncCloseCalls
}

func (t *directConsumerTracker) waitForPartitionConsumer(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		t.mu.Lock()
		created := len(t.partitionConsumers)
		t.mu.Unlock()
		if created > 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func (t *directConsumerTracker) snapshot() ([]*trackedPartitionConsumer, int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	partitions := append([]*trackedPartitionConsumer(nil), t.partitionConsumers...)
	return partitions, t.asyncCloses, t.closeCalls
}

// TestDirectReadDeadlineInterruptsQueuedSubscriptions reproduces the wide
// partition, slow broker case: 64 partitions with 100ms per response would
// keep the subscription busy for about 6.4s. The 1s preview deadline must
// interrupt the queued Sarama requests and return well before that backlog
// finishes, and the cleanup budget must not be spent waiting for the broker.
func TestDirectReadDeadlineInterruptsQueuedSubscriptions(t *testing.T) {
	const partitions = 64
	broker := newSlowWideBroker(t, "wide-topic", partitions, 100*time.Millisecond)
	defer broker.Close()

	cfg := directTestConfig(1000, time.Second)
	cfg.Hosts = []string{broker.Addr()}
	cfg.Topics = []string{"wide-topic"}

	input := newDirectTestInput(t, cfg, &fakeOutlet{}, nil)
	start := time.Now()
	err := runDirectToCompletion(t, input)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.True(t, elapsed < 2*time.Second,
		"64 queued offset requests at 100ms would take 6.4s; the preview returned after %s", elapsed)
}

// TestDirectReadCancellationInterruptsQueuedSubscriptions checks the same
// interruption on an explicit cancel instead of the deadline. The preview
// timeout is far away, so only the cancellation can end the queued
// subscription calls. The tracker factory pre-subscribes one partition so a
// real partition consumer exists when the cancel fires, while every other
// subscription is still queued behind the slow broker.
func TestDirectReadCancellationInterruptsQueuedSubscriptions(t *testing.T) {
	const partitions = 64
	broker := newSlowWideBroker(t, "wide-topic", partitions, 100*time.Millisecond)
	defer broker.Close()

	cfg := directTestConfig(1000, 30*time.Second)
	cfg.Hosts = []string{broker.Addr()}
	cfg.Topics = []string{"wide-topic"}

	tracker := newDirectConsumerTracker("wide-topic", 0)
	input := newDirectTestInput(t, cfg, &fakeOutlet{}, tracker.factory)
	input.Run()
	require.True(t, waitForOffsetRequest(broker, 2*time.Second),
		"the slow broker never received an offset request")
	// The pre-subscribed partition consumer must be handed to the preview before
	// cancelling; the remaining partitions are still queued behind the slow
	// broker. This only bounds the setup; the latency assertion is below.
	require.True(t, tracker.waitForPartitionConsumer(2*time.Second),
		"the pre-created partition consumer was not handed to the preview before cancellation")

	cancelStart := time.Now()
	close(input.context.Done)
	select {
	case <-input.completion:
	case <-time.After(4 * time.Second):
		t.Fatal("direct read did not complete after cancellation")
	}
	elapsed := time.Since(cancelStart)
	require.Error(t, input.CompletionErr())
	assert.Contains(t, input.CompletionErr().Error(), "canceled")
	assert.True(t, elapsed < 2*time.Second, "cancellation took %s, want less than 2s", elapsed)

	// The in-flight subscriptions are abandoned by the cancellation, so their
	// partition consumers must be shut down and the direct consumer closed
	// exactly once. Without these assertions a regression could leak every
	// partition consumer while the test still only measured the runtime.
	createdPartitions, asyncCloses, closeCalls := tracker.snapshot()
	require.NotEmpty(t, createdPartitions,
		"cancellation must be asserted against at least one created partition consumer")
	for _, partition := range createdPartitions {
		assert.Equal(t, 1, partition.asyncCloseCount(),
			"partition consumer %s/%d must be AsyncClosed exactly once",
			partition.topic, partition.partition)
	}
	assert.Equal(t, len(createdPartitions), asyncCloses,
		"every created partition consumer must be AsyncClosed")
	assert.Equal(t, 1, closeCalls, "directConsumer.Close must be called exactly once")
}

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

// TestDirectReadMissingTopicMetadataPreflight is the wire-level guard for the
// read-only preview guarantee: a typo or deleted topic must be detected by the
// stock-API preflight, using only full metadata refreshes. Stock Sarama sends
// a topic-scoped MetadataRequest with allow_auto_topic_creation=true (Kafka
// 1.0+) once a named topic is missing from its cache, and that request is what
// could create the topic. No request in the broker history may name a topic.
func TestDirectReadMissingTopicMetadataPreflight(t *testing.T) {
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

	fullRequests := 0
	for _, exchange := range broker.History() {
		request, ok := exchange.Request.(*sarama.MetadataRequest)
		if !ok {
			continue
		}
		assert.Equal(t, 0, len(request.Topics),
			"the read-only preview must only send full metadata requests, got %v", request.Topics)
		// Full metadata requests always disable auto topic creation. For v4+
		// the flag is on the wire; older versions simply cannot encode it, so
		// assert the version too instead of relying on a zero-value flag.
		assert.True(t, int(request.Version) >= 4,
			"full metadata request %d must use v4+ so the auto-create flag is on the wire, got v%d",
			fullRequests, request.Version)
		assert.False(t, request.AllowAutoTopicCreation,
			"full metadata request %d must not allow auto topic creation", fullRequests)
		fullRequests++
	}
	// One full refresh comes from sarama.NewClient, the other from the explicit
	// preflight RefreshMetadata call.
	assert.True(t, fullRequests >= 2,
		"the preview must refresh metadata at least twice, saw %d", fullRequests)
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
// and deadline tests can assert the cleanup contract and not only the
// completion timing. The factory mirrors the production one (a real Sarama
// client and consumer); only the returned consumers are wrapped.
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
	closed             bool
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
	err := c.directConsumer.Close()
	c.tracker.mu.Lock()
	c.tracker.closed = true
	c.tracker.mu.Unlock()
	return err
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

// waitForCleanup waits until the late subscription cleanup closed the client
// and every partition consumer it created exactly once. The abort path returns
// long before this happens; tests assert it separately instead of timing
// Completion().
func (t *directConsumerTracker) waitForCleanup(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if t.cleanupDone() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return t.cleanupDone()
}

func (t *directConsumerTracker) cleanupDone() bool {
	t.mu.Lock()
	partitions := append([]*trackedPartitionConsumer(nil), t.partitionConsumers...)
	closeCalls, closed := t.closeCalls, t.closed
	t.mu.Unlock()
	if closeCalls != 1 || !closed {
		return false
	}
	for _, partition := range partitions {
		if partition.asyncCloseCount() != 1 {
			return false
		}
	}
	return true
}

func (t *directConsumerTracker) snapshot() ([]*trackedPartitionConsumer, int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	partitions := append([]*trackedPartitionConsumer(nil), t.partitionConsumers...)
	return partitions, t.asyncCloses, t.closeCalls
}

// TestDirectReadDeadlineInterruptsQueuedSubscriptions reproduces the wide
// partition, slow broker case: 64 partitions with 100ms per response would
// keep the subscription busy for seconds. The 1s preview deadline must return
// without waiting for the queued requests or the late cleanup; the
// subscription goroutine closes every late partition consumer and the client
// exactly once afterwards.
func TestDirectReadDeadlineInterruptsQueuedSubscriptions(t *testing.T) {
	const partitions = 64
	broker := newSlowWideBroker(t, "wide-topic", partitions, 100*time.Millisecond)
	defer broker.Close()

	cfg := directTestConfig(1000, time.Second)
	cfg.Hosts = []string{broker.Addr()}
	cfg.Topics = []string{"wide-topic"}

	tracker := newDirectConsumerTracker("wide-topic", 0)
	input := newDirectTestInput(t, cfg, &fakeOutlet{}, tracker.factory)
	start := time.Now()
	err := runDirectToCompletion(t, input)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.True(t, elapsed < 2*time.Second,
		"the preview returned after %s, want less than 2s despite queued broker requests", elapsed)

	require.True(t, tracker.waitForCleanup(30*time.Second),
		"the late subscription cleanup did not finish")
	createdPartitions, asyncCloses, closeCalls := tracker.snapshot()
	require.NotEmpty(t, createdPartitions,
		"the deadline must be asserted against at least one created partition consumer")
	for _, partition := range createdPartitions {
		assert.Equal(t, 1, partition.asyncCloseCount(),
			"partition consumer %s/%d must be AsyncClosed exactly once",
			partition.topic, partition.partition)
	}
	assert.Equal(t, len(createdPartitions), asyncCloses,
		"every created partition consumer must be AsyncClosed")
	assert.Equal(t, 1, closeCalls, "directConsumer.Close must be called exactly once")
}

// TestDirectReadCancellationInterruptsQueuedSubscriptions checks the same
// interruption and late cleanup on an explicit cancel instead of the deadline.
// The preview timeout is far away, so only the cancellation can end the queued
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
	// exactly once by the subscription goroutine. Without these assertions a
	// regression could leak every partition consumer while the test still only
	// measured the runtime.
	require.True(t, tracker.waitForCleanup(30*time.Second),
		"the late subscription cleanup did not finish")
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

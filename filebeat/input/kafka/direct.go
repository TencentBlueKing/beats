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
	"sync"
	"time"

	"github.com/Shopify/sarama"

	"github.com/elastic/beats/filebeat/util"
	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common/backoff"
)

const (
	// Direct-read resource limits. These only apply to the preview branch; the
	// consumer-group branch keeps the values built by newSaramaConfig untouched.
	directChannelBufferSize = 2
	directFetchMaxBytes     = 4 << 20
	directMaxPartitions     = 128
	directMaxMessageBytes   = 10 << 20
	directConnectAttempts   = 2
	directNetTimeoutCap     = 10 * time.Second
	// directReaderShutdownBudget bounds partition-reader and consumer close
	// after the read window. A stuck broker close must not hold Completion()
	// open; the external timeout remains the process-level backstop.
	directReaderShutdownBudget = 5 * time.Second
)

// directConsumer is the narrow Sarama consumer surface used by the direct
// branch. It is intentionally small so unit tests do not need a real broker.
type directConsumer interface {
	Partitions(topic string) ([]int32, error)
	ConsumePartition(topic string, partition int32, offset int64) (sarama.PartitionConsumer, error)
	Close() error
}

type directConsumerFactory func(addrs []string, conf *sarama.Config) (directConsumer, error)

type directPartition struct {
	topic     string
	partition int32
	pc        sarama.PartitionConsumer
}

type directMessage struct {
	topic     string
	partition int32
	message   *sarama.ConsumerMessage
}

// consumeDirect is the terminal function of the direct branch. It always
// returns through the same cleanup path; the caller completes the input once.
func (input *kafkaInput) consumeDirect() error {
	cfg := input.config.DirectRead
	if cfg == nil || !cfg.Enabled {
		return errors.New("direct read is not enabled")
	}
	if cfg.MaxEvents == nil || cfg.Timeout == nil {
		return errors.New("direct read requires max_events and timeout")
	}

	deadline := time.Now().Add(*cfg.Timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-input.context.Done:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() {
		cancel()
		<-watchDone
	}()

	saramaConfig := *input.saramaConfig
	if err := applyDirectLimits(&saramaConfig, *cfg.Timeout); err != nil {
		return err
	}

	factory := input.directConsumerFactory
	if factory == nil {
		factory = func(addrs []string, conf *sarama.Config) (directConsumer, error) {
			return sarama.NewConsumer(addrs, conf)
		}
	}

	consumer, err := input.connectDirect(ctx, deadline, factory, &saramaConfig)
	if err != nil {
		return err
	}

	partitions, err := input.subscribeDirect(ctx, deadline, consumer)
	if err != nil {
		input.closeDirectPartitions(partitions)
		_ = consumer.Close()
		return err
	}
	// A deadline or cancellation that fired before the subscription was fully
	// established is a failure, even if the last ConsumePartition call happened
	// to return successfully.
	if err := ctx.Err(); err != nil {
		input.closeDirectPartitions(partitions)
		_ = consumer.Close()
		return directAbortError(ctx, deadline, "before subscribing to kafka partitions")
	}

	return input.runDirectLoop(ctx, consumer, partitions)
}

// applyDirectLimits copies newSaramaConfig's result for the direct branch. Only
// bounded-read limits are changed; TLS, SASL, version and consumer parameters
// shared with the consumer-group path are left untouched.
func applyDirectLimits(cfg *sarama.Config, timeout time.Duration) error {
	cfg.ChannelBufferSize = directChannelBufferSize
	cfg.Consumer.Fetch.Max = directFetchMaxBytes

	maxWait := timeout / 5
	if maxWait > time.Second {
		maxWait = time.Second
	}
	if maxWait <= 0 {
		maxWait = time.Millisecond
	}
	cfg.Consumer.MaxWaitTime = maxWait

	netTimeout := timeout
	if netTimeout > directNetTimeoutCap {
		netTimeout = directNetTimeoutCap
	}
	cfg.Net.DialTimeout = netTimeout
	cfg.Net.ReadTimeout = netTimeout
	cfg.Net.WriteTimeout = netTimeout

	// Keep one jittered retry; the default of three long backoffs can outlive
	// a short preview window.
	cfg.Metadata.Retry.Max = 1

	// The 4MiB fetch cap can otherwise leave a user-configured fetch.default
	// larger than Fetch.Max. Clamp it; Sarama's Validate does not check this.
	if cfg.Consumer.Fetch.Max > 0 && cfg.Consumer.Fetch.Default > cfg.Consumer.Fetch.Max {
		cfg.Consumer.Fetch.Default = cfg.Consumer.Fetch.Max
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("direct read: invalid sarama config: %w", err)
	}
	return nil
}

// connectDirect creates the Sarama consumer with a bounded number of attempts.
// The timeout starts before the first connection attempt, and backoff waits are
// interruptible through the deadline/cancellation context.
func (input *kafkaInput) connectDirect(
	ctx context.Context,
	deadline time.Time,
	factory directConsumerFactory,
	saramaConfig *sarama.Config,
) (directConsumer, error) {
	timeout := *input.config.DirectRead.Timeout

	initialBackoff := input.config.ConnectBackoff
	if initialBackoff <= 0 {
		initialBackoff = 500 * time.Millisecond
	}
	if initialBackoff > timeout/4 {
		initialBackoff = timeout / 4
	}
	if initialBackoff < 10*time.Millisecond {
		initialBackoff = 10 * time.Millisecond
	}
	retryBackoff := backoff.NewEqualJitterBackoff(ctx.Done(), initialBackoff, 8*initialBackoff)

	var lastErr error
	for attempt := 0; attempt < directConnectAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, directAbortError(ctx, deadline, "before connecting to kafka")
		}

		consumer, err := input.dialDirect(ctx, deadline, factory, saramaConfig)
		if err == nil {
			return consumer, nil
		}
		// A deadline or cancellation during dial is already a terminal preview
		// error. Do not replace it with the factory's own failure.
		if ctx.Err() != nil {
			return nil, err
		}
		lastErr = err

		if attempt == directConnectAttempts-1 {
			break
		}
		retryBackoff.Wait()
	}

	if err := ctx.Err(); err != nil {
		return nil, directAbortError(ctx, deadline, "before connecting to kafka")
	}
	if lastErr == nil {
		lastErr = errors.New("unknown connection error")
	}
	return nil, fmt.Errorf("direct read: connecting to kafka: %w", lastErr)
}

// subscribeDirect resolves partitions and creates one partition consumer per
// partition. Reaching the deadline during this phase is a failure: a preview
// that never established a healthy subscription must not look like an empty
// topic.
func (input *kafkaInput) subscribeDirect(
	ctx context.Context,
	deadline time.Time,
	consumer directConsumer,
) ([]*directPartition, error) {
	partitions := make(map[string][]int32, len(input.config.Topics))
	total := 0
	for _, topic := range input.config.Topics {
		if err := ctx.Err(); err != nil {
			return nil, directAbortError(ctx, deadline, "before subscribing to kafka partitions")
		}

		topicPartitions, err := consumer.Partitions(topic)
		if err != nil {
			return nil, fmt.Errorf("direct read: fetching partitions for topic %q: %w", topic, err)
		}
		if len(topicPartitions) == 0 {
			return nil, fmt.Errorf("direct read: topic %q has no partitions", topic)
		}
		total += len(topicPartitions)
		if total > directMaxPartitions {
			return nil, fmt.Errorf("direct read: %d partitions exceed the limit of %d", total, directMaxPartitions)
		}
		partitions[topic] = topicPartitions
	}

	result := make([]*directPartition, 0, total)
	// initial_offset is shared with the consumer-group path and still defaults
	// to newest. newest reads only messages produced after the subscription;
	// a preview of data that already exists must set oldest explicitly.
	offset := input.config.InitialOffset.asSaramaOffset()
	for _, topic := range input.config.Topics {
		for _, partition := range partitions[topic] {
			if err := ctx.Err(); err != nil {
				return result, directAbortError(ctx, deadline, "before subscribing to kafka partitions")
			}

			pc, err := consumer.ConsumePartition(topic, partition, offset)
			if err != nil {
				return result, fmt.Errorf("direct read: consuming %s/%d: %w", topic, partition, err)
			}
			result = append(result, &directPartition{topic: topic, partition: partition, pc: pc})
		}
	}
	return result, nil
}

// dialDirect runs one connection attempt without letting it ignore the
// preview deadline. The factory may still finish after cancellation; any
// consumer it created is closed instead of being returned.
func (input *kafkaInput) dialDirect(
	ctx context.Context,
	deadline time.Time,
	factory directConsumerFactory,
	saramaConfig *sarama.Config,
) (directConsumer, error) {
	type dialResult struct {
		consumer directConsumer
		err      error
	}
	result := make(chan dialResult, 1)
	go func() {
		consumer, err := factory(input.config.Hosts, saramaConfig)
		result <- dialResult{consumer: consumer, err: err}
	}()

	select {
	case <-ctx.Done():
		go func() {
			res := <-result
			if res.consumer != nil {
				_ = res.consumer.Close()
			}
		}()
		return nil, directAbortError(ctx, deadline, "before connecting to kafka")
	case res := <-result:
		if err := ctx.Err(); err != nil {
			if res.consumer != nil {
				_ = res.consumer.Close()
			}
			return nil, directAbortError(ctx, deadline, "before connecting to kafka")
		}
		return res.consumer, res.err
	}
}

// runDirectLoop owns the single aggregation outlet, the event budget and the
// shutdown of all readers. Partition goroutines only read; all expansion and
// OnEvent calls happen here so one message expanding to many events cannot
// overshoot max_events. Cleanup is deferred so a panic still closes partition
// consumers. A consumer error drained after the readers exit wins over a
// deadline, which would otherwise look like an empty successful preview.
func (input *kafkaInput) runDirectLoop(
	ctx context.Context,
	consumer directConsumer,
	partitions []*directPartition,
) (terminalErr error) {
	stopCh := make(chan struct{})
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() { close(stopCh) })
	}

	var readers sync.WaitGroup
	messages := make(chan directMessage)
	readErr := make(chan error, 1)

	for _, partition := range partitions {
		readers.Add(1)
		go func(p *directPartition) {
			defer readers.Done()
			input.readDirectPartition(p, messages, readErr, stopCh)
		}(partition)
	}

	maxEvents := *input.config.DirectRead.MaxEvents
	sent := 0
	defer func() {
		stop()
		input.closeDirectPartitions(partitions)
		if err := waitDirectReaders(&readers); err != nil && terminalErr == nil && sent < maxEvents {
			terminalErr = err
		}
		// Readers send before returning. Drain only after they have finished, and
		// do not turn a full successful budget into a failure because shutdown
		// itself produced a late error.
		if err := drainDirectReadErr(readErr); err != nil && terminalErr == nil && sent < maxEvents {
			terminalErr = err
		}
		if err := closeDirectConsumer(consumer); err != nil && terminalErr == nil && sent < maxEvents {
			terminalErr = err
		}
		if terminalErr == nil && sent < maxEvents {
			if err := ctx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
				terminalErr = errors.New("direct read: canceled while reading")
			}
		}
	}()

	for sent < maxEvents {
		select {
		case <-ctx.Done():
			return
		case err := <-readErr:
			terminalErr = err
			return
		case message := <-messages:
			if ctx.Err() != nil {
				return
			}
			events := createEvents(
				input.config.Version,
				input.config.ExpandEventListFromField,
				input.log,
				message.topic,
				message.partition,
				message.message,
			)
			for i := range events {
				if sent >= maxEvents {
					return
				}
				if err := input.publishDirectEvent(ctx, events[i]); err != nil {
					terminalErr = err
					return
				}
				sent++
			}
		}
	}
	return
}

// readDirectPartition forwards messages until it is stopped. Sarama closes
// Messages before Errors, and a select can observe the closed Messages channel
// while an error is still buffered. Both channels are drained to completion;
// a closed channel is set to nil so it drops out of the select.
func (input *kafkaInput) readDirectPartition(
	partition *directPartition,
	messages chan<- directMessage,
	readErr chan<- error,
	stopCh <-chan struct{},
) {
	forward := true
	stop := stopCh
	messageCh := partition.pc.Messages()
	errorCh := partition.pc.Errors()
	for messageCh != nil || errorCh != nil {
		select {
		case message, ok := <-messageCh:
			if !ok {
				messageCh = nil
				continue
			}
			if message == nil || !forward {
				continue
			}
			if size := consumerMessageSize(message); size > directMaxMessageBytes {
				input.reportDirectReadErr(readErr, fmt.Errorf(
					"direct read: message %s/%d offset %d is %d bytes, limit is %d",
					partition.topic, partition.partition, message.Offset, size, directMaxMessageBytes))
				forward = false
				stop = nil
				continue
			}
			select {
			case messages <- directMessage{
				topic:     partition.topic,
				partition: partition.partition,
				message:   message,
			}:
			case <-stopCh:
				forward = false
				stop = nil
			}

		case err, ok := <-errorCh:
			if !ok {
				errorCh = nil
				continue
			}
			if !forward || err == nil {
				continue
			}
			input.reportDirectReadErr(readErr, fmt.Errorf(
				"direct read: consumer error %s/%d: %w",
				partition.topic, partition.partition, err))
			forward = false
			stop = nil

		case <-stop:
			forward = false
			stop = nil
		}
	}
}

func (input *kafkaInput) reportDirectReadErr(readErr chan<- error, err error) {
	select {
	case readErr <- err:
	default:
	}
}

// publishDirectEvent delivers one event without letting a blocked outlet hold
// the read loop past the preview deadline. The OnEvent call itself may still
// be running after this returns; closing the outlet or exiting the process
// unblocks it.
func (input *kafkaInput) publishDirectEvent(ctx context.Context, event beat.Event) error {
	if err := directDeliveryAbort(ctx.Err()); err != nil {
		return err
	}
	type publishResult struct {
		ok    bool
		panic interface{}
	}
	done := make(chan publishResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- publishResult{panic: r}
			}
		}()
		done <- publishResult{ok: input.outlet.OnEvent(&util.Data{Event: event})}
	}()
	select {
	case result := <-done:
		if result.panic != nil {
			return fmt.Errorf("direct read: panic: %v", result.panic)
		}
		if !result.ok {
			return errors.New("direct read: outlet rejected an event")
		}
		return nil
	case <-ctx.Done():
		return directDeliveryAbort(ctx.Err())
	}
}

func directDeliveryAbort(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("direct read: timed out delivering an event")
	}
	return errors.New("direct read: canceled while delivering an event")
}

func waitDirectReaders(readers *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		readers.Wait()
		close(done)
	}()
	timer := time.NewTimer(directReaderShutdownBudget)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New("direct read: timed out waiting for partition readers to stop")
	}
}

func closeDirectConsumer(consumer directConsumer) error {
	done := make(chan error, 1)
	go func() {
		done <- consumer.Close()
	}()
	timer := time.NewTimer(directReaderShutdownBudget)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("direct read: closing kafka consumer: %w", err)
		}
		return nil
	case <-timer.C:
		return errors.New("direct read: timed out closing kafka consumer")
	}
}

func drainDirectReadErr(readErr <-chan error) error {
	select {
	case err := <-readErr:
		return err
	default:
		return nil
	}
}

func (input *kafkaInput) closeDirectPartitions(partitions []*directPartition) {
	for _, partition := range partitions {
		partition.pc.AsyncClose()
	}
}

func consumerMessageSize(message *sarama.ConsumerMessage) int {
	size := len(message.Key) + len(message.Value)
	for _, header := range message.Headers {
		size += len(header.Key) + len(header.Value)
	}
	return size
}

func directAbortError(ctx context.Context, deadline time.Time, stage string) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || time.Now().After(deadline) {
		return fmt.Errorf("direct read: timed out %s", stage)
	}
	return fmt.Errorf("direct read: canceled %s", stage)
}

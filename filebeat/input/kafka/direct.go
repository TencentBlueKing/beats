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
	applyDirectLimits(&saramaConfig, *cfg.Timeout)

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
func applyDirectLimits(cfg *sarama.Config, timeout time.Duration) {
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

		consumer, err := factory(input.config.Hosts, saramaConfig)
		if err == nil {
			return consumer, nil
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

// runDirectLoop owns the single aggregation outlet, the event budget and the
// shutdown of all readers. Partition goroutines only read; all expansion and
// OnEvent calls happen here so one message expanding to many events cannot
// overshoot max_events.
func (input *kafkaInput) runDirectLoop(
	ctx context.Context,
	consumer directConsumer,
	partitions []*directPartition,
) error {
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
	var terminalErr error
loop:
	for {
		if sent >= maxEvents {
			break
		}

		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				// The subscription is healthy and the read window expired; fewer
				// than max_events (or zero) is a normal preview result.
				break loop
			}
			terminalErr = errors.New("direct read: canceled while reading")
			break loop

		case err := <-readErr:
			terminalErr = err
			break loop

		case message := <-messages:
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
					break
				}
				if !input.outlet.OnEvent(&util.Data{Event: events[i]}) {
					terminalErr = errors.New("direct read: outlet rejected an event")
					break loop
				}
				sent++
			}
		}
	}

	stop()
	input.closeDirectPartitions(partitions)
	readers.Wait()
	if err := consumer.Close(); err != nil && terminalErr == nil {
		terminalErr = fmt.Errorf("direct read: closing kafka consumer: %w", err)
	}
	return terminalErr
}

// readDirectPartition forwards messages until it is stopped. After a stop it
// keeps draining Messages/Errors until Sarama closes them, so closing the
// partition consumer cannot block on an unread channel.
func (input *kafkaInput) readDirectPartition(
	partition *directPartition,
	messages chan<- directMessage,
	readErr chan<- error,
	stopCh <-chan struct{},
) {
	forward := true
	stop := stopCh
	for {
		select {
		case message, ok := <-partition.pc.Messages():
			if !ok {
				return
			}
			if message == nil {
				continue
			}
			if !forward {
				continue
			}
			if size := consumerMessageSize(message); size > directMaxMessageBytes {
				select {
				case readErr <- fmt.Errorf(
					"direct read: message %s/%d offset %d is %d bytes, limit is %d",
					partition.topic, partition.partition, message.Offset, size, directMaxMessageBytes):
				default:
				}
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

		case err, ok := <-partition.pc.Errors():
			if !ok {
				return
			}
			if !forward || err == nil {
				continue
			}
			select {
			case readErr <- fmt.Errorf(
				"direct read: consumer error %s/%d: %w",
				partition.topic, partition.partition, err):
			default:
			}
			forward = false
			stop = nil

		case <-stop:
			forward = false
			stop = nil
		}
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

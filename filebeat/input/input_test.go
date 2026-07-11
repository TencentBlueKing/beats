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

//go:build !integration
// +build !integration

package input

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNextScanIntervalDefaultsToBase(t *testing.T) {
	SetAdaptiveScanIntervalFunc(nil)

	base := 10 * time.Second
	assert.Equal(t, base, nextScanInterval(1, base, time.Millisecond))
}

func TestNextScanIntervalUsesHookContext(t *testing.T) {
	defer SetAdaptiveScanIntervalFunc(nil)

	const inputID = uint64(42)
	base := 10 * time.Second
	scanDuration := 25 * time.Millisecond
	want := 500 * time.Millisecond

	SetAdaptiveScanIntervalFunc(func(gotID uint64, gotBase, gotScanDuration time.Duration) time.Duration {
		assert.Equal(t, inputID, gotID)
		assert.Equal(t, base, gotBase)
		assert.Equal(t, scanDuration, gotScanDuration)
		return want
	})

	assert.Equal(t, want, nextScanInterval(inputID, base, scanDuration))
}

func TestNextScanIntervalFallsBackForNonPositiveResult(t *testing.T) {
	defer SetAdaptiveScanIntervalFunc(nil)

	base := 10 * time.Second
	for _, invalid := range []time.Duration{0, -time.Second} {
		SetAdaptiveScanIntervalFunc(func(uint64, time.Duration, time.Duration) time.Duration {
			return invalid
		})
		assert.Equal(t, base, nextScanInterval(1, base, time.Millisecond))
	}
}

func TestAdaptiveScanRunnerIDsAreUnique(t *testing.T) {
	first := nextAdaptiveScanRunnerID()
	second := nextAdaptiveScanRunnerID()

	assert.NotEqual(t, first, second)
	assert.NotZero(t, first)
	assert.NotZero(t, second)
}

// controlledInput 通过 release 精确控制每轮 Run 的结束时机，
// 用于验证传给回调的是各轮独立测量的真实耗时，而不是复用首轮结果。
type controlledInput struct {
	started chan struct{}
	release chan struct{}
}

func (i *controlledInput) Reload() {}
func (i *controlledInput) Run() {
	i.started <- struct{}{}
	<-i.release
}
func (i *controlledInput) Stop() {}
func (i *controlledInput) Wait() {}

func TestRunnerUsesMeasuredScanDurationForNextInterval(t *testing.T) {
	defer SetAdaptiveScanIntervalFunc(nil)

	type hookCall struct {
		inputID      uint64
		base         time.Duration
		scanDuration time.Duration
	}

	const inputID = uint64(99)
	base := time.Hour
	hookCalls := make(chan hookCall, 2)
	SetAdaptiveScanIntervalFunc(func(id uint64, base, scanDuration time.Duration) time.Duration {
		hookCalls <- hookCall{id, base, scanDuration}
		return time.Millisecond
	})

	input := &controlledInput{
		started: make(chan struct{}, 2),
		release: make(chan struct{}, 2),
	}
	runner := &Runner{
		config:         inputConfig{ScanFrequency: base},
		input:          input,
		done:           make(chan struct{}),
		ID:             7,
		adaptiveScanID: inputID,
	}
	finished := make(chan struct{})
	go func() {
		runner.Run()
		close(finished)
	}()

	select {
	case <-input.started:
	case <-time.After(time.Second):
		t.Fatal("initial input run did not happen")
	}
	time.Sleep(2 * time.Millisecond)
	input.release <- struct{}{}

	var firstScanDuration time.Duration
	select {
	case call := <-hookCalls:
		assert.Equal(t, inputID, call.inputID)
		assert.Equal(t, base, call.base)
		assert.True(t, call.scanDuration > 0)
		firstScanDuration = call.scanDuration
	case <-time.After(time.Second):
		t.Fatal("adaptive interval hook was not called after initial scan")
	}

	select {
	case <-input.started:
	case <-time.After(time.Second):
		t.Fatal("adaptive interval was not used to schedule the next scan")
	}
	time.Sleep(20 * time.Millisecond)
	input.release <- struct{}{}

	select {
	case call := <-hookCalls:
		assert.True(t, call.scanDuration > 5*firstScanDuration)
	case <-time.After(time.Second):
		t.Fatal("adaptive interval hook was not called after the second scan")
	}

	close(runner.done)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("runner did not stop")
	}
}

type immediateInput struct{}

func (*immediateInput) Reload() {}
func (*immediateInput) Run()    {}
func (*immediateInput) Stop()   {}
func (*immediateInput) Wait()   {}

func TestRunnerOnceDoesNotCallAdaptiveIntervalHook(t *testing.T) {
	defer SetAdaptiveScanIntervalFunc(nil)

	called := make(chan struct{}, 1)
	SetAdaptiveScanIntervalFunc(func(uint64, time.Duration, time.Duration) time.Duration {
		called <- struct{}{}
		return time.Millisecond
	})

	runner := &Runner{
		config: inputConfig{ScanFrequency: time.Hour},
		input:  &immediateInput{},
		done:   make(chan struct{}),
		Once:   true,
	}
	runner.Run()

	select {
	case <-called:
		t.Fatal("once runner must not calculate another scan interval")
	default:
	}
}

func TestRunnerDoesNotCallAdaptiveIntervalHookWhenStoppedAfterScan(t *testing.T) {
	defer SetAdaptiveScanIntervalFunc(nil)

	called := make(chan struct{}, 1)
	SetAdaptiveScanIntervalFunc(func(uint64, time.Duration, time.Duration) time.Duration {
		called <- struct{}{}
		return time.Millisecond
	})

	done := make(chan struct{})
	close(done)
	runner := &Runner{
		config: inputConfig{ScanFrequency: time.Hour},
		input:  &immediateInput{},
		done:   done,
	}
	runner.Run()

	select {
	case <-called:
		t.Fatal("stopped runner must not calculate another scan interval")
	default:
	}
}

func TestAdaptiveScanIntervalFuncCanBeReplacedConcurrently(t *testing.T) {
	defer SetAdaptiveScanIntervalFunc(nil)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				SetAdaptiveScanIntervalFunc(nil)
				return
			}
			SetAdaptiveScanIntervalFunc(func(_ uint64, base, _ time.Duration) time.Duration {
				return base
			})
		}(i)
		go func() {
			defer wg.Done()
			assert.True(t, nextScanInterval(1, time.Second, time.Millisecond) > 0)
		}()
	}
	wg.Wait()
}

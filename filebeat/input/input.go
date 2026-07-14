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

package input

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mitchellh/hashstructure"

	"github.com/elastic/beats/filebeat/channel"
	filebeatconfig "github.com/elastic/beats/filebeat/config"
	"github.com/elastic/beats/filebeat/input/file"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/monitoring"
)

// AdaptiveScanIntervalFunc 根据 Runner 实例标识、配置的基础扫描周期和上一轮扫描耗时，
// 计算下一轮扫描周期。多个 Runner 会并发调用该函数，回调实现必须保证并发安全且快速返回。
type AdaptiveScanIntervalFunc func(inputID uint64, base, lastScan time.Duration) time.Duration

// AdaptiveScanAppliedFunc 接收 Beats 归一化后的最终扫描周期。
// requested 是上层计算值，applied 是 Runner 实际用于等待的值；该回调同样必须并发安全且快速返回。
type AdaptiveScanAppliedFunc func(inputID uint64, base, requested, applied, lastScan time.Duration)

// AdaptiveScanHooks 将周期计算与最终结果通知绑定为同一代配置，避免 Reload 时新旧回调错配。
type AdaptiveScanHooks struct {
	Interval AdaptiveScanIntervalFunc
	Applied  AdaptiveScanAppliedFunc
}

var (
	inputList = monitoring.NewUniqueList()

	// 锁只保护整组 hooks 的替换和读取，回调本身在锁外执行，
	// 避免慢回调长期阻塞配置更新，也避免回调内部更新钩子时发生死锁。
	adaptiveScanHookSet = struct {
		sync.RWMutex
		hooks AdaptiveScanHooks
	}{}
	// 原 Runner.ID 是配置哈希，相同配置的新旧 Runner 在异步 Reload 时可能短暂重叠，
	// 因此使用进程内唯一序号隔离两个实例的自适应状态。
	adaptiveScanRunnerSequence uint64
)

func init() {
	monitoring.NewFunc(monitoring.GetNamespace("state").GetRegistry(), "input", inputList.Report, monitoring.Report)
}

// SetAdaptiveScanHooks 原子替换进程级自适应扫描 hooks，传入零值时恢复使用配置的扫描周期。
// 该方法不是同步屏障：调用返回时，替换前已被 Runner 取出的旧回调仍可能正在执行，
// 因此调用方必须保证回调持有的状态可被并发访问，且在旧回调退出前仍然有效。
func SetAdaptiveScanHooks(hooks AdaptiveScanHooks) {
	adaptiveScanHookSet.Lock()
	adaptiveScanHookSet.hooks = hooks
	adaptiveScanHookSet.Unlock()
}

// SetAdaptiveScanIntervalFunc 兼容仅设置周期计算回调的调用方，不注册最终结果通知。
func SetAdaptiveScanIntervalFunc(fn AdaptiveScanIntervalFunc) {
	SetAdaptiveScanHooks(AdaptiveScanHooks{Interval: fn})
}

func nextScanInterval(inputType string, inputID uint64, base, lastScan time.Duration) time.Duration {
	// log 与 docker 都会在 Run 中重复扫描文件路径；其他 input 的 Run 可能包含连接、
	// 重置或一次性启动语义，必须维持原调用周期，也不能把耗时计入文件扫描 governor。
	if inputType != filebeatconfig.DefaultType && inputType != "docker" {
		return base
	}

	// 一次复制整组 hooks，确保本轮计算和通知始终来自同一代配置。
	adaptiveScanHookSet.RLock()
	hooks := adaptiveScanHookSet.hooks
	adaptiveScanHookSet.RUnlock()

	if hooks.Interval == nil {
		return base
	}

	requested := hooks.Interval(inputID, base, lastScan)
	applied := requested
	// 非正周期或超过配置上限都回退到原配置，保证自适应扫描不会劣化既有扫描频率。
	if requested <= 0 || requested > base {
		applied = base
	}
	if hooks.Applied != nil {
		hooks.Applied(inputID, base, requested, applied, lastScan)
	}
	return applied
}

func nextAdaptiveScanRunnerID() uint64 {
	// uint64 零值即计数器初始值，首次 Add 返回 1，无需额外初始化。
	return atomic.AddUint64(&adaptiveScanRunnerSequence, 1)
}

// Input is the interface common to all input
type Input interface {
	Reload()
	Run()
	Stop()
	Wait()
}

// Runner encapsulate the lifecycle of the input
type Runner struct {
	config   inputConfig
	input    Input
	done     chan struct{}
	wg       *sync.WaitGroup
	ID       uint64
	Once     bool
	beatDone chan struct{}

	// 仅用于关联进程内本次 Runner 生命周期对应的自适应状态。
	adaptiveScanID uint64
}

// New instantiates a new Runner
func New(
	conf *common.Config,
	outlet channel.Connector,
	beatDone chan struct{},
	states []file.State,
	dynFields *common.MapStrPointer,
) (*Runner, error) {
	input := &Runner{
		config:         defaultConfig,
		wg:             &sync.WaitGroup{},
		done:           make(chan struct{}),
		Once:           false,
		beatDone:       beatDone,
		adaptiveScanID: nextAdaptiveScanRunnerID(),
	}

	var err error
	if err = conf.Unpack(&input.config); err != nil {
		return nil, err
	}

	var h map[string]interface{}
	conf.Unpack(&h)
	input.ID, err = hashstructure.Hash(h, nil)
	if err != nil {
		return nil, err
	}

	var f Factory
	f, err = GetFactory(input.config.Type)
	if err != nil {
		return input, err
	}

	context := Context{
		States:        states,
		Done:          input.done,
		BeatDone:      input.beatDone,
		DynamicFields: dynFields,
		Meta:          nil,
	}
	var ipt Input
	ipt, err = f(conf, outlet, context)
	if err != nil {
		return input, err
	}
	input.input = ipt

	return input, nil
}

// Start starts the input
func (p *Runner) Start() {
	p.wg.Add(1)
	logp.Info("Starting input of type: %v; ID: %d ", p.config.Type, p.ID)

	onceWg := sync.WaitGroup{}
	if p.Once {
		// Make sure start is only completed when Run did a complete first scan
		defer onceWg.Wait()
	}

	onceWg.Add(1)
	inputList.Add(p.config.Type)
	// Add waitgroup to make sure input is finished
	go func() {
		defer func() {
			onceWg.Done()
			p.stop()
			p.wg.Done()
		}()

		p.Run()
	}()
}

// Run starts scanning through all the file paths and fetch the related files. Start a harvester for each file
func (p *Runner) Run() {
	// 启动后仍然立即执行首轮扫描，同时记录真实耗时，作为下一轮周期的计算依据。
	scanStarted := time.Now()
	p.input.Run()
	lastScan := time.Since(scanStarted)

	// Once 模式只执行首轮扫描，不需要计算一个永远不会使用的下一轮周期。
	if p.Once {
		return
	}

	for {
		// 先检查停止信号，避免 Runner 已停止时仍调用一次外部周期计算回调。
		select {
		case <-p.done:
			logp.Info("input ticker stopped")
			return
		default:
		}

		// 每轮重新读取钩子，使运行中的 Runner 无需重建即可响应配置 Reload。
		interval := nextScanInterval(p.config.Type, p.AdaptiveScanID(), p.config.ScanFrequency, lastScan)
		// 前一个 select 只负责在计算前快速退出；这里负责在实际等待期间响应停止信号。
		select {
		case <-p.done:
			logp.Info("input ticker stopped")
			return
		case <-time.After(interval):
			logp.Debug("input", "Run input")
			scanStarted = time.Now()
			p.input.Run()
			lastScan = time.Since(scanStarted)
		}
	}
}

// AdaptiveScanID 返回自适应扫描状态使用的进程内唯一实例标识。
// 它与基于配置哈希生成的 ID 分离，避免异步 Reload 期间相同配置的新旧 Runner 状态冲突。
// 对测试或旧代码直接构造、尚未分配实例标识的 Runner，回退使用原 ID。
func (p *Runner) AdaptiveScanID() uint64 {
	if p.adaptiveScanID != 0 {
		return p.adaptiveScanID
	}
	return p.ID
}

// Reload reload the input for states
func (p *Runner) Reload() {
	p.input.Reload()
}

// Stop stops the input and with it all harvesters
func (p *Runner) Stop() {
	// Stop scanning and wait for completion
	close(p.done)
	p.wg.Wait()
	inputList.Remove(p.config.Type)
}

func (p *Runner) stop() {
	logp.Info("Stopping Input: %d", p.ID)

	// In case of once, it will be waited until harvesters close itself
	if p.Once {
		p.input.Wait()
	} else {
		p.input.Stop()
	}
}

func (p *Runner) String() string {
	return fmt.Sprintf("input [type=%s, ID=%d]", p.config.Type, p.ID)
}

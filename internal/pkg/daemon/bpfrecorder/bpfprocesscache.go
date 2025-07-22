//go:build linux && !no_bpf
// +build linux,!no_bpf

/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bpfrecorder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
)

var ErrBpfLoad = errors.New("unable to load BPF")

const CmdLineNotFound = "Unable to find cmdLine"
const EnvNotFound = "Unable to find env"

type BpfProcessInfo struct {
	Pid     int
	CmdLine string
	Env     map[string]string
}

type BpfProcessCache struct {
	recorder *BpfRecorder
	logger   logr.Logger
	cache    *ttlcache.Cache[int, *BpfProcessInfo]
}

func NewBpfProcessCache(logger logr.Logger) (*BpfProcessCache, error) {
	bpfProcCache := &BpfProcessCache{
		recorder: New("", logger, false, false),
		logger:   logger,
		cache: ttlcache.New(
			ttlcache.WithTTL[int, *BpfProcessInfo](processCacheTimeout),
			ttlcache.WithCapacity[int, *BpfProcessInfo](maxCacheItems),
		),
	}

	if err := Load(logger, bpfProcCache); err != nil {
		logger.Error(err, "failed to load process cache")
		return nil, ErrBpfLoad
	}

	return bpfProcCache, nil
}

func Load(logger logr.Logger, b *BpfProcessCache) (err error) {
	var module *bpf.Module

	logger.Info("Loading bpf module...")

	var bpfObject []byte

	switch b.recorder.GoArch() {
	case "amd64":
		bpfObject = bpfAmd64
	case "arm64":
		bpfObject = bpfArm64
	default:
		return fmt.Errorf("architecture %s is currently unsupported", runtime.GOARCH)
	}

	module, err = b.recorder.NewModuleFromBufferArgs(&bpf.NewModuleArgs{
		BPFObjBuff: bpfObject,
		BPFObjName: "recorder.bpf.o",
		BTFObjPath: b.recorder.btfPath,
	})

	if err != nil {
		return fmt.Errorf("load bpf module: %w", err)
	}

	b.recorder.module = module

	b.logger.Info("Loading bpf object from module")

	if err := b.recorder.BPFLoadObject(module); err != nil {
		return fmt.Errorf("load bpf object: %w", err)
	}

	procCacheHooks := []string{
		"sys_enter_execve",
		"sys_enter_getgid",
	}

	if err := b.recorder.loadPrograms(procCacheHooks); err != nil {
		return fmt.Errorf("loading base hooks: %w", err)
	}

	b.recorder.isRecordingBpfMap, err = b.recorder.GetMap(b.recorder.module, "is_recording")
	if err != nil {
		return fmt.Errorf("getting `is_recording` map: %w", err)
	}

	const timeout = 300

	events := make(chan []byte)

	ringbuf, err := b.recorder.InitRingBuf(
		b.recorder.module,
		"events",
		events,
	)
	if err != nil {
		return fmt.Errorf("init events ringbuffer: %w", err)
	}

	b.recorder.PollRingBuffer(ringbuf, timeout)

	go b.processEvents(events) //TODO

	b.logger.Info("BPF module successfully loaded.")

	if err := b.recorder.StartRecording(); err != nil {
		return fmt.Errorf("StartRecording self-test: %w", err)
	}

	b.logger.Info("Started Recorder")

	go b.cache.Start()

	return nil
}

func (b *BpfProcessCache) GetCmdLine(pid int) (cmdLine string, err error) {
	item := b.cache.Get(pid)
	if item != nil {
		return item.Value().CmdLine, nil
	}

	return "", errors.New("no process info for Pid")
}

func (b *BpfProcessCache) GetEnv(pid int) (env map[string]string, err error) {
	item := b.cache.Get(pid)
	if item != nil {
		return item.Value().Env, nil
	}

	return nil, errors.New("no process info for Pid")
}

func (b *BpfProcessCache) processEvents(events chan []byte) {
	b.logger.Info("Processing bpf events")
	defer b.logger.Info("Stopped processing bpf events")

	for event := range events {
		b.handleEvent(event)
	}
}

func (b *BpfProcessCache) handleEvent(eventBytes []byte) {
	var execEvent bpfExecEvent
	errExecEvent := binary.Read(bytes.NewReader(eventBytes), binary.LittleEndian, &execEvent)
	if errExecEvent != nil {
		b.logger.Error(errExecEvent, "Couldn't read event structure")

		return
	}

	b.logger.Info("eventTypeExecevEnter received", "execEvent", &execEvent)

	var cmdLine string
	for i := 0; i < len(execEvent.Args); i++ {
		cmdLine += string(execEvent.Args[i][:])
		if i < len(execEvent.Args)-1 {
			cmdLine += " "
		}
	}

	envMap := make(map[string]string)

	for i := 0; i < len(execEvent.Env); i++ {
		envVar := string(execEvent.Env[i][:])

		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]
			envMap[key] = value
		}
	}

	pInfo := &BpfProcessInfo{
		Pid:     int(execEvent.Pid),
		CmdLine: string(execEvent.Filename[:]) + cmdLine,
		Env:     envMap,
	}

	b.cache.Set(int(execEvent.Pid), pInfo, ttlcache.DefaultTTL)
	b.logger.Info("eventTypeExecevEnter processed", "pInfo", &pInfo)
}

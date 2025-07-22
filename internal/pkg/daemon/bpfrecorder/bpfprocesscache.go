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

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
)

var ErrBpfLoad = errors.New("unable to load BPF")

const CmdLineNotFound = "Unable to find cmdLine"
const EnvNotFound = "Unable to find env"

type BpfProcessCache struct {
	recorder *BpfRecorder
	logger   logr.Logger
}

func NewBpfProcessCache(logger logr.Logger) (*BpfProcessCache, error) {
	bpfProcCache := &BpfProcessCache{
		recorder: New("", logger, false, false),
		logger:   logger,
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

	return nil
}

func (b *BpfProcessCache) GetCmdLine(pid int) (cmdLine string, err error) {
	// TODO
	return "", nil
}

func (b *BpfProcessCache) GetEnv(pid int) (env map[string]string, err error) {
	// TODO
	return nil, nil
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
}

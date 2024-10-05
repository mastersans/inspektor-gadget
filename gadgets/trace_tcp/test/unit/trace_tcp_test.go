// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"fmt"
	"net"
	"testing"
	"time"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceTcpEvent struct {
	Comm string `json:"comm"`
	Pid  int    `json:"pid"`
	Tid  int    `json:"tid"`
	Uid  uint32 `json:"uid"`
	Gid  uint32 `json:"gid"`
	Type string `json:"type"`

	MntNsId int `json:"mntns_id"`

	NetNsId int              `json:"netns_id"`
	Src     utils.L4Endpoint `json:"src"`
	Dst     utils.L4Endpoint `json:"dst"`
}

type testDef struct {
	addr          string
	port          int
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func(t *testing.T, addr string, port int)
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceTcpEvent) error
}

func TestTraceTcpGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	testCases := map[string]testDef{
		"captures_all_events_1": {
			addr:          "127.0.0.1",
			port:          9070,
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceTcpEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					return &ExpectedTraceTcpEvent{
						Comm:    info.Comm,
						Pid:     info.Pid,
						Tid:     info.Tid,
						Uid:     0,
						Gid:     0,
						Type:    "close",
						MntNsId: int(info.MountNsID),
						NetNsId: int(info.NetworkNsID),
						Src: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    utils.NormalizedInt,
							Proto:   6,
						},
						Dst: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    9070,
							Proto:   6,
						},
					}
				})(t, info, fd, events)
				return nil
			},
		},
		"captures_all_events_2": {
			addr:          "127.0.0.1",
			port:          9160,
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceTcpEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedTraceTcpEvent {
					return &ExpectedTraceTcpEvent{
						Comm:    info.Comm,
						Pid:     info.Pid,
						Tid:     info.Tid,
						Uid:     0,
						Gid:     0,
						Type:    "close",
						MntNsId: int(info.MountNsID),
						NetNsId: int(info.NetworkNsID),
						Src: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    utils.NormalizedInt,
							Proto:   6,
						},
						Dst: utils.L4Endpoint{
							Addr:    "127.0.0.1",
							Version: 4,
							Port:    9160,
							Proto:   6,
						},
					}
				})(t, info, fd, events)
				return nil
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			params := map[string]string{
				"operator.LocalManager.host": "true",
			}
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			Opts := gadgetrunner.GadgetOpts[ExpectedTraceTcpEvent]{
				Image:        "trace_tcp",
				Timeout:      5 * time.Second,
				MnsFilterMap: nil,
				ApiParams:    params,
			}

			gdgt := gadgetrunner.NewGadget(t, Opts)
			gdgt.NormalizeEvent = func(event *ExpectedTraceTcpEvent) {
				utils.NormalizeInt(&event.Src.Port)
			}

			gdgt.OnGadgetRun = func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					testCase.generateEvent(t, testCase.addr, testCase.port)
					return nil
				})
				return nil
			}

			gdgt.RunGadget()

			testCase.validateEvent(t, runner.Info, 0, gdgt.CapturedEvents)
		})
	}
}

func generateEvent(t *testing.T, addr string, port int) {
	net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
}

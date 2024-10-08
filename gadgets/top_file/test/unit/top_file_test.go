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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTopFileEvent struct {
	Comm    string `json:"comm"`
	Dev     uint32 `json:"dev"`
	File    string `json:"file"`
	Gid     uint32 `json:"gid"`
	MntnsID uint64 `json:"mntns_id"`
	Pid     int    `json:"pid"`
	Tid     int    `json:"tid"`
	Uid     uint32 `json:"uid"`
	RBytes  uint64 `json:"rbytes"`
	Reads   uint64 `json:"reads"`
	WBytes  uint64 `json:"wbytes"`
	Writes  uint64 `json:"writes"`
	T       string `json:"t"`
}

type testDef struct {
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func(t *testing.T) string
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, filepath string, events []ExpectedTopFileEvent)
	mnsFilterMap  func(info *utilstest.RunnerInfo) *ebpf.Map
}

func TestTopFileGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	runnerConfig := &utilstest.RunnerConfig{}

	testCases := map[string]testDef{
		"captures_events_with_filter": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			mnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, filepath string, events []ExpectedTopFileEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedTopFileEvent {
					return &ExpectedTopFileEvent{
						Comm: "bash",
						T:    "R",
						File: filepath,

						// Only check the existence of pid as bash creates subshell
						Pid: utils.NormalizedInt,
						Tid: utils.NormalizedInt,

						// Only check the existence.
						Writes: utils.NormalizedInt,
						WBytes: utils.NormalizedInt,

						MntnsID: info.MountNsID,
						Uid:     0,
						Gid:     0,
						Dev:     0,

						// Nothing is being read from the file.
						Reads:  0,
						RBytes: 0,
					}
				})(t, info, 0, events)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var filepath string
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			params := map[string]string{
				"operator.oci.ebpf.map-fetch-interval": "1000ms",
				"operator.LocalManager.host":           "true",
				"operator.oci.verify-image":            "false",
			}

			var MnsFilterMap *ebpf.Map
			if testCase.mnsFilterMap != nil {
				MnsFilterMap = testCase.mnsFilterMap(runner.Info)
			}
			Opts := gadgetrunner.GadgetOpts[ExpectedTopFileEvent]{
				Image:        "top_file",
				Timeout:      5 * time.Second,
				MnsFilterMap: MnsFilterMap,
				ApiParams:    params,
			}

			gdgt := gadgetrunner.NewGadget(t, Opts)
			gdgt.NormalizeEvent = func(event *ExpectedTopFileEvent) {
				utils.NormalizeInt(&event.Tid)
				utils.NormalizeInt(&event.Pid)
				utils.NormalizeInt(&event.WBytes)
				utils.NormalizeInt(&event.Writes)
			}
			gdgt.BeforeGadgetRun = func() error {
				utilstest.RunWithRunner(t, runner, func() error {
					filepath = testCase.generateEvent(t)
					return nil
				})
				return nil
			}

			gdgt.RunGadget()

			testCase.validateEvent(t, runner.Info, filepath, gdgt.CapturedEvents)
		})
	}
}
func generateEvent(t *testing.T) string {
	wd, err := os.Getwd()
	require.NoError(t, err, "getting current working directory")

	filepath := filepath.Join(wd, "bar")
	file, err := os.Create(filepath)
	require.NoError(t, err, "creating file")

	defer func() {
		err := file.Close()
		require.NoError(t, err, "closing file")
	}()

	// Set up the command to continuously write to the file with a 5 seconds timeout
	cmd := exec.Command("bash", "-c", "timeout 5 bash -c 'while true; do echo -n foo > bar; sleep 0.3; done'")
	cmd.Dir = wd
	err = cmd.Start()
	require.NoError(t, err, "starting command")

	t.Cleanup(func() {
		os.Remove(filepath)
	})

	return filepath
}

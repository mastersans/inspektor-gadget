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
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

type ExpectedTraceOpenEvent struct {
	Comm     string `json:"comm"`
	Pid      int    `json:"pid"`
	Tid      int    `json:"tid"`
	Uid      uint32 `json:"uid"`
	Gid      uint32 `json:"gid"`
	Fd       uint32 `json:"fd"`
	FName    string `json:"fname"`
	FlagsRaw int    `json:"flags_raw"`
	ModeRaw  int    `json:"mode_raw"`
	ErrRaw   int    `json:"error_raw"`
}

type testDef struct {
	runnerConfig  *utilstest.RunnerConfig
	mntsFilterMap func(info *utilstest.RunnerInfo) *ebpf.Map
	generateEvent func(t *testing.T) int
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent)
}

func TestTraceOpenGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	testCases := map[string]testDef{
		"captures_all_events_with_no_filters_configured": {
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:  info.Comm,
						Pid:   info.Pid,
						Tid:   info.Tid,
						Uid:   uint32(info.Uid),
						Gid:   uint32(info.Gid),
						Fd:    uint32(fd),
						FName: "/dev/null",
					}
				})(t, info, fd, events)
			},
		},
		"captures_no_events_with_no_matching_filter": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, 0)
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectNoEvent(t, info, fd, events)
			},
		},
		"captures_events_with_matching_filter": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:  info.Comm,
						Pid:   info.Pid,
						Tid:   info.Tid,
						Uid:   uint32(info.Uid),
						Gid:   uint32(info.Gid),
						Fd:    uint32(fd),
						FName: "/dev/null",
					}
				})(t, info, fd, events)
			},
		},
		"test_flags_and_mode": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: func(t *testing.T) int {
				filename := "/tmp/test_flags_and_mode"
				fd, err := unix.Open(filename, unix.O_CREAT|unix.O_RDWR, unix.S_IRWXU|unix.S_IRGRP|unix.S_IWGRP|unix.S_IXOTH)
				require.NoError(t, err, "opening file")
				defer os.Remove(filename)
				unix.Close(fd)

				return fd
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:     info.Comm,
						Pid:      info.Pid,
						Tid:      info.Tid,
						Uid:      uint32(info.Uid),
						Gid:      uint32(info.Gid),
						Fd:       uint32(fd),
						FName:    "/tmp/test_flags_and_mode",
						FlagsRaw: unix.O_CREAT | unix.O_RDWR,
						ModeRaw:  unix.S_IRWXU | unix.S_IRGRP | unix.S_IWGRP | unix.S_IXOTH,
						ErrRaw:   0,
					}
				})(t, info, fd, events)
			},
		},
		"test_symbolic_links": {
			runnerConfig: &utilstest.RunnerConfig{},
			generateEvent: func(t *testing.T) int {
				// Create a symbolic link to /dev/null
				err := os.Symlink("/dev/null", "/tmp/test_symbolic_links")
				if err != nil {
					require.NoError(t, err, "creating a symbolic link")
					return 0
				}
				defer os.Remove("/tmp/test_symbolic_links")

				// Open the symbolic link
				fd, err := unix.Open("/tmp/test_symbolic_links", unix.O_RDONLY, 0)
				if err != nil {
					require.NoError(t, err, "opening the symbolic link")
					return 0
				}
				defer unix.Close(fd)

				return fd
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:     info.Comm,
						Pid:      info.Pid,
						Tid:      info.Tid,
						Uid:      uint32(info.Uid),
						Gid:      uint32(info.Gid),
						Fd:       uint32(fd),
						FName:    "/tmp/test_symbolic_links",
						FlagsRaw: 0,
						ModeRaw:  0,
						ErrRaw:   0,
					}
				})(t, info, fd, events)
			},
		},
		"test_relative_path": {
			runnerConfig: &utilstest.RunnerConfig{},
			generateEvent: func(t *testing.T) int {
				relPath := generateRelativePathForAbsolutePath(t, "/tmp/test_relative_path")
				fd, err := unix.Open(relPath, unix.O_CREAT|unix.O_RDWR, unix.S_IRWXU|unix.S_IRGRP|unix.S_IWGRP|unix.S_IXOTH)
				require.NoError(t, err, "opening file")

				defer os.Remove(relPath)

				unix.Close(fd)

				return fd
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:     info.Comm,
						Pid:      info.Pid,
						Tid:      info.Tid,
						Uid:      uint32(info.Uid),
						Gid:      uint32(info.Gid),
						Fd:       uint32(fd),
						FName:    generateRelativePathForAbsolutePath(t, "/tmp/test_relative_path"),
						FlagsRaw: 66,
						ModeRaw:  497,
						ErrRaw:   0,
					}
				})(t, info, fd, events)
			},
		},
		"test_prefix_on_directory": {
			runnerConfig: &utilstest.RunnerConfig{},
			generateEvent: func(t *testing.T) int {
				err := os.Mkdir("/tmp/foo", 0o750)
				require.NoError(t, err, "mkdir for /tmp/foo")

				defer os.RemoveAll("/tmp/foo")

				fd, err := unix.Open("/tmp/foo/bar.test", unix.O_RDONLY|unix.O_CREAT, 0)
				require.NoError(t, err, "opening /tmp/foo")

				defer unix.Close(fd)

				badfd, err := unix.Open("/tmp/quux.test", unix.O_RDONLY|unix.O_CREAT, 0)
				require.NoError(t, err, "opening /tmp/quux.test")

				defer unix.Close(badfd)

				return fd
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:     info.Comm,
						Pid:      info.Pid,
						Tid:      info.Tid,
						Uid:      uint32(info.Uid),
						Gid:      uint32(info.Gid),
						Fd:       uint32(fd),
						FName:    "/tmp/foo/bar.test",
						ErrRaw:   0,
						FlagsRaw: unix.O_RDONLY | unix.O_CREAT,
						ModeRaw:  0,
					}
				})(t, info, fd, events)
			}},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var fd int
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			apiParams := map[string]string{
				"operator.oci.ebpf.uid": "0",
			}
			var mntsFilterMap *ebpf.Map
			if testCase.mntsFilterMap != nil {
				mntsFilterMap = testCase.mntsFilterMap(runner.Info)
			}
			opts := gadgetrunner.GadgetOpts[ExpectedTraceOpenEvent]{
				Image:        "trace_open",
				Timeout:      5 * time.Second,
				MnsFilterMap: mntsFilterMap,
				ApiParams:    apiParams,
			}
			gdgt := gadgetrunner.NewGadget(
				t, opts,
			)
			gdgt.OnGadgetRun = func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					fd = testCase.generateEvent(t)
					return nil
				})
				return nil
			}
			gdgt.RunGadget()

			testCase.validateEvent(t, runner.Info, fd, gdgt.CapturedEvents)
		})
	}
}
func generateRelativePathForAbsolutePath(t *testing.T, fileName string) string {
	// If the filename is relative, return it as is
	if !filepath.IsAbs(fileName) {
		return fileName
	}

	cwd, err := os.Getwd()
	require.NoError(t, err, "getting current working directory")

	relPath, err := filepath.Rel(cwd, fileName)
	require.NoError(t, err, "getting relative path")

	return relPath
}

// generateEvent simulates an event by opening and closing a file
func generateEvent(t *testing.T) int {
	fd, err := unix.Open("/dev/null", 0, 0)
	require.NoError(t, err, "opening file")

	// Close the file descriptor to simulate the event
	err = unix.Close(fd)
	require.NoError(t, err, "closing file")

	return fd
}

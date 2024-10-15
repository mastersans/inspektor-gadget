// Copyright 2023 The Inspektor Gadget authors
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

package main

import (
	"fmt"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	tcprttProfileTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/tcprtt/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/histogram"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
)

func TestProfileTCPRTT(t *testing.T) {
	t.Parallel()

	serverPodName := "nginx-pod"
	clientPodName := "test-pod"
	ns := GenerateTestNamespaceName("test-profile-tcprtt")

	startServerCommands := []TestStep{
		CreateTestNamespaceCommand(ns),
		PodCommand(serverPodName, "docker.io/library/nginx:latest", ns, "", ""),
		WaitUntilPodReadyCommand(ns, serverPodName),
	}
	RunTestSteps(startServerCommands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))

	t.Cleanup(func() {
		cleanupCommands := []TestStep{
			DeleteTestNamespaceCommand(ns),
		}
		RunTestSteps(cleanupCommands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	serverIP := GetTestPodIP(t, ns, serverPodName)

	generateTrafficCommands := []TestStep{
		BusyboxPodRepeatCommand(ns, fmt.Sprintf("wget -q -O /dev/null %s:80", serverIP)),
		WaitUntilTestPodReadyCommand(ns),
	}
	RunTestSteps(generateTrafficCommands, t, WithCbBeforeCleanup(PrintLogsFn()))

	clientIP := GetTestPodIP(t, ns, clientPodName)

	// Filtering by node doesn't make sense for ig but just for kubectl-gadget.
	var clientNode string
	if DefaultTestComponent == InspektorGadgetTestComponent {
		clientNode = GetPodNode(t, ns, clientPodName)
	}

	t.Run("DefaultParams", func(t *testing.T) {
		t.Parallel()

		topTCPCmd := newProfileTCPRTTCmd(
			"",
			true,
			clientNode,
			histogram.UnitMicroseconds,
			tcprttProfileTypes.AddressTypeAll,
			tcprttProfileTypes.WildcardAddress,
			0,
			0,
		)
		RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	// TODO: Why without timeout the topTCPCmd command doesn't generate any output?
	// t.Run("DefaultParamsWithoutTimeout", func(t *testing.T) {
	// 	t.Parallel()

	// 	topTCPCmd := newProfileTCPRTTCmd(
	// 		"",
	// 		false,
	// 		filterByNode,
	// 		serverNode,
	// 		histogram.UnitMicroseconds,
	// 		tcprttProfileTypes.AddressTypeAll,
	// 		tcprttProfileTypes.WildcardAddress,
	// 	)
	// 	RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	// })

	t.Run("FilterRemotePort", func(t *testing.T) {
		t.Parallel()

		flags := "--rport 80"
		topTCPCmd := newProfileTCPRTTCmd(
			flags,
			true,
			clientNode,
			histogram.UnitMicroseconds,
			tcprttProfileTypes.AddressTypeAll,
			tcprttProfileTypes.WildcardAddress,
			0,
			80,
		)
		RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("FilterRemoteAddr", func(t *testing.T) {
		t.Parallel()

		flags := fmt.Sprintf("--raddr %s", serverIP)
		topTCPCmd := newProfileTCPRTTCmd(
			flags,
			true,
			clientNode,
			histogram.UnitMicroseconds,
			tcprttProfileTypes.AddressTypeAll,
			tcprttProfileTypes.WildcardAddress,
			0,
			0,
		)
		RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("FilterLocalAddr", func(t *testing.T) {
		t.Parallel()

		flags := fmt.Sprintf("--laddr %s", clientIP)
		topTCPCmd := newProfileTCPRTTCmd(
			flags,
			true,
			clientNode,
			histogram.UnitMicroseconds,
			tcprttProfileTypes.AddressTypeAll,
			tcprttProfileTypes.WildcardAddress,
			0,
			0,
		)
		RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("ByRemoteAndFilterLocalAddr", func(t *testing.T) {
		t.Parallel()

		flags := fmt.Sprintf("--byraddr --laddr %s", clientIP)
		topTCPCmd := newProfileTCPRTTCmd(
			flags,
			true,
			clientNode,
			histogram.UnitMicroseconds,
			tcprttProfileTypes.AddressTypeRemote,
			serverIP,
			0,
			0,
		)
		RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("ByLocalAndFilterRemoteAddr", func(t *testing.T) {
		t.Parallel()

		flags := fmt.Sprintf("--byladdr --raddr %s", serverIP)
		topTCPCmd := newProfileTCPRTTCmd(
			flags,
			true,
			clientNode,
			histogram.UnitMicroseconds,
			tcprttProfileTypes.AddressTypeLocal,
			clientIP,
			0,
			0,
		)
		RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})

	t.Run("MillisecondsAndFilterRemoteAndLocalAddr", func(t *testing.T) {
		t.Parallel()

		flags := fmt.Sprintf("--milliseconds --raddr %s --laddr %s", serverIP, clientIP)
		topTCPCmd := newProfileTCPRTTCmd(
			flags,
			true,
			clientNode,
			histogram.UnitMilliseconds,
			tcprttProfileTypes.AddressTypeAll,
			tcprttProfileTypes.WildcardAddress,
			0,
			0,
		)
		RunTestSteps([]TestStep{topTCPCmd}, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
	})
}

func newProfileTCPRTTCmd(flags string, useTimeout bool, node string, unit histogram.Unit, addressType tcprttProfileTypes.AddressType, addr string, localPort uint16, remotePort uint16) *Command {
	cmd := fmt.Sprintf("%s profile tcprtt -o json %s", DefaultTestComponent, flags)

	if useTimeout {
		cmd += " --timeout 10"
	}
	if node != "" {
		cmd += fmt.Sprintf(" --node %s", node)
	}

	return &Command{
		Name:         "ProfileTCPRTT",
		Cmd:          cmd,
		StartAndStop: !useTimeout,
		ValidateOutput: func(t *testing.T, output string) {
			expectedEntry := &tcprttProfileTypes.Report{
				Histograms: []*tcprttProfileTypes.ExtendedHistogram{
					tcprttProfileTypes.NewHistogram(unit, nil, addressType, addr, 1, localPort, remotePort),
				},
			}

			normalize := func(r *tcprttProfileTypes.Report) {
				if len(r.Histograms) != 1 {
					return
				}

				r.Histograms[0].Intervals = nil

				if r.Histograms[0].Average != 0 {
					r.Histograms[0].Average = 1
				}

				// TODO: Verify this also when using milliseconds once gadget
				// will be able to report the total latencies between 0 and 1.
				// Otherwise, the test will fail because the average latency
				// will always be 0 milliseconds, so there is no way to verify
				// that it was computed correctly.
				if r.Histograms[0].Unit == histogram.UnitMilliseconds {
					r.Histograms[0].Average = 1
				}
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	}
}

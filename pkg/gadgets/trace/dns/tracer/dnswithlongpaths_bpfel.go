// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type dnsWithLongPathsEventT struct {
	Netns     uint32
	_         [4]byte
	Timestamp uint64
	MountNsId uint64
	Pid       uint32
	Tid       uint32
	Ppid      uint32
	Uid       uint32
	Gid       uint32
	Comm      [16]uint8
	Pcomm     [16]uint8
	SaddrV6   [16]uint8
	DaddrV6   [16]uint8
	Af        uint16
	Sport     uint16
	Dport     uint16
	DnsOff    uint16
	Proto     uint8
	PktType   uint8
	_         [2]byte
	LatencyNs uint64
	Cwd       [4096]uint8
	Exepath   [4096]uint8
}

type dnsWithLongPathsQueryKeyT struct {
	PidTgid uint64
	Id      uint16
	Pad     [3]uint16
}

type dnsWithLongPathsSocketsKey struct {
	Netns  uint32
	Family uint16
	Proto  uint8
	_      [1]byte
	Port   uint16
	_      [2]byte
}

type dnsWithLongPathsSocketsValue struct {
	Mntns             uint64
	PidTgid           uint64
	UidGid            uint64
	Task              [16]int8
	Ptask             [16]int8
	Sock              uint64
	DeletionTimestamp uint64
	Cwd               [4096]int8
	Exepath           [4096]int8
	Ppid              uint32
	Ipv6only          int8
	_                 [3]byte
}

// loadDnsWithLongPaths returns the embedded CollectionSpec for dnsWithLongPaths.
func loadDnsWithLongPaths() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_DnsWithLongPathsBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load dnsWithLongPaths: %w", err)
	}

	return spec, err
}

// loadDnsWithLongPathsObjects loads dnsWithLongPaths and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*dnsWithLongPathsObjects
//	*dnsWithLongPathsPrograms
//	*dnsWithLongPathsMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadDnsWithLongPathsObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadDnsWithLongPaths()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// dnsWithLongPathsSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dnsWithLongPathsSpecs struct {
	dnsWithLongPathsProgramSpecs
	dnsWithLongPathsMapSpecs
}

// dnsWithLongPathsSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dnsWithLongPathsProgramSpecs struct {
	IgTraceDns *ebpf.ProgramSpec `ebpf:"ig_trace_dns"`
}

// dnsWithLongPathsMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dnsWithLongPathsMapSpecs struct {
	Events        *ebpf.MapSpec `ebpf:"events"`
	GadgetSockets *ebpf.MapSpec `ebpf:"gadget_sockets"`
	QueryMap      *ebpf.MapSpec `ebpf:"query_map"`
	TmpEvents     *ebpf.MapSpec `ebpf:"tmp_events"`
}

// dnsWithLongPathsObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadDnsWithLongPathsObjects or ebpf.CollectionSpec.LoadAndAssign.
type dnsWithLongPathsObjects struct {
	dnsWithLongPathsPrograms
	dnsWithLongPathsMaps
}

func (o *dnsWithLongPathsObjects) Close() error {
	return _DnsWithLongPathsClose(
		&o.dnsWithLongPathsPrograms,
		&o.dnsWithLongPathsMaps,
	)
}

// dnsWithLongPathsMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadDnsWithLongPathsObjects or ebpf.CollectionSpec.LoadAndAssign.
type dnsWithLongPathsMaps struct {
	Events        *ebpf.Map `ebpf:"events"`
	GadgetSockets *ebpf.Map `ebpf:"gadget_sockets"`
	QueryMap      *ebpf.Map `ebpf:"query_map"`
	TmpEvents     *ebpf.Map `ebpf:"tmp_events"`
}

func (m *dnsWithLongPathsMaps) Close() error {
	return _DnsWithLongPathsClose(
		m.Events,
		m.GadgetSockets,
		m.QueryMap,
		m.TmpEvents,
	)
}

// dnsWithLongPathsPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadDnsWithLongPathsObjects or ebpf.CollectionSpec.LoadAndAssign.
type dnsWithLongPathsPrograms struct {
	IgTraceDns *ebpf.Program `ebpf:"ig_trace_dns"`
}

func (p *dnsWithLongPathsPrograms) Close() error {
	return _DnsWithLongPathsClose(
		p.IgTraceDns,
	)
}

func _DnsWithLongPathsClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed dnswithlongpaths_bpfel.o
var _DnsWithLongPathsBytes []byte

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

package datasource

import (
	"crypto/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// Missing tests:
// - GetFieldsWithTag()
// - Subfields

func TestDataSourceDuplicatedField(t *testing.T) {
	t.Parallel()

	ds := New(TypeSingle, "event")

	_, err := ds.AddField("foo", api.Kind_Int8)
	require.NoError(t, err)

	_, err = ds.AddField("foo", api.Kind_Int32)
	require.Error(t, err)
}

func TestDataSourceNonExistingField(t *testing.T) {
	t.Parallel()

	ds := New(TypeSingle, "event")

	acc := ds.GetField("foo")
	require.Nil(t, acc)
}

func TestDataSourceEmptyField(t *testing.T) {
	t.Parallel()

	ds := New(TypeSingle, "event")

	// See https://github.com/inspektor-gadget/inspektor-gadget/issues/2817
	acc, err := ds.AddField("foo", api.Kind_Invalid, WithFlags(FieldFlagEmpty))
	require.NoError(t, err)

	d, err := ds.NewPacketSingle()
	require.NoError(t, err)
	defer ds.Release(d)

	err = acc.Set(d, []byte{0x01, 0x02, 0x03})
	require.Error(t, err)

	ret := acc.Get(d)
	require.Nil(t, ret)
}

type fieldT struct {
	name string
	typ  api.Kind
	val  any
}

var fields = []*fieldT{
	{"field_bool", api.Kind_Bool, bool(true)},
	{"field_int8", api.Kind_Int8, int8(-123)},
	{"field_int16", api.Kind_Int16, int16(-25647)},
	{"field_int32", api.Kind_Int32, int32(-535245564)},
	{"field_int64", api.Kind_Int64, int64(-1234567890)},
	{"field_uint8", api.Kind_Uint8, uint8(56)},
	{"field_uint16", api.Kind_Uint16, uint16(12345)},
	{"field_uint32", api.Kind_Uint32, uint32(1234567890)},
	{"field_uint64", api.Kind_Uint64, uint64(1234567890123456)},
	{"field_float32", api.Kind_Float32, float32(3.14159)},
	{"field_float64", api.Kind_Float64, float64(3.14159265359)},
	{"field_string", api.Kind_String, string("Hello, World!")},
	{"field_bytes", api.Kind_Bytes, []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
}

func TestDataSourceAddFields(t *testing.T) {
	t.Parallel()

	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			ds := New(TypeSingle, "event")
			acc, err := ds.AddField(f.name, f.typ)
			require.NoError(t, err)

			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			defer ds.Release(data)

			switch f.typ {
			case api.Kind_Bool:
				acc.PutBool(data, f.val.(bool))
				val := acc.Bool(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Int8:
				acc.PutInt8(data, f.val.(int8))
				val := acc.Int8(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Int16:
				acc.PutInt16(data, f.val.(int16))
				val := acc.Int16(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Int32:
				acc.PutInt32(data, f.val.(int32))
				val := acc.Int32(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Int64:
				acc.PutInt64(data, f.val.(int64))
				val := acc.Int64(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Uint8:
				acc.PutUint8(data, f.val.(uint8))
				val := acc.Uint8(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Uint16:
				acc.PutUint16(data, f.val.(uint16))
				val := acc.Uint16(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Uint32:
				acc.PutUint32(data, f.val.(uint32))
				val := acc.Uint32(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Uint64:
				acc.PutUint64(data, f.val.(uint64))
				val := acc.Uint64(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Float32:
				acc.PutFloat32(data, f.val.(float32))
				val := acc.Float32(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Float64:
				acc.PutFloat64(data, f.val.(float64))
				val := acc.Float64(data)
				assert.Equal(t, f.val, val)
			case api.Kind_String:
				acc.PutString(data, f.val.(string))
				val := acc.String(data)
				assert.Equal(t, f.val, val)
			case api.Kind_Bytes:
				acc.PutBytes(data, f.val.([]byte))
				val := acc.Bytes(data)
				assert.Equal(t, f.val, val)
			}
		})
	}
}

func TestBadAccesors(t *testing.T) {
	t.Parallel()

	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			ds := New(TypeSingle, "event")
			acc, err := ds.AddField(f.name, f.typ)
			require.NoError(t, err)

			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			defer ds.Release(data)

			// Test that it doesn't explode by setting the wrong type
			acc.PutBool(data, bool(true))
			acc.PutInt8(data, int8(-123))
			acc.PutInt16(data, int16(-25647))
			acc.PutInt32(data, int32(-535245564))
			acc.PutInt64(data, int64(-1234567890))
			acc.PutUint8(data, uint8(56))
			acc.PutUint16(data, uint16(12345))
			acc.PutUint32(data, uint32(1234567890))
			acc.PutUint64(data, uint64(123456789012345))
			acc.PutFloat32(data, float32(3.14159))
			acc.PutFloat64(data, float64(3.14159265359))
			acc.PutString(data, string("Hello, World!"))
			acc.PutBytes(data, []byte{0x01, 0x02, 0x03, 0x04, 0x05})
		})
	}
}

func TestDataSourceStaticFields(t *testing.T) {
	t.Parallel()

	ds := New(TypeSingle, "event")

	fields := []StaticField{
		&dummyField{
			name:   "f1",
			size:   4,
			offset: 0,
		},
		&dummyField{
			name:   "f2",
			size:   4,
			offset: 4,
		},
		&dummyField{
			name:   "f3",
			size:   2,
			offset: 8,
		},
		&dummyField{
			name:   "f4",
			size:   1,
			offset: 10,
		},
		// 1-byte hole
		&dummyField{
			name:   "f5",
			size:   8,
			offset: 12,
		},
	}

	totalSize := uint32(4 + 4 + 2 + 1 + 8 + 1) // all sizes above + 1 byte for padding

	acc, err := ds.AddStaticFields(totalSize, fields)
	require.NoError(t, err)

	d, err := ds.NewPacketSingle()
	require.NoError(t, err)
	defer ds.Release(d)

	// Try to write full blob with smaller data
	err = acc.Set(d, randBytes(3))
	require.Error(t, err)

	// Try to write full blob with bigger data
	err = acc.Set(d, randBytes(int(totalSize+1)))
	require.Error(t, err)

	// Try to read/write all fields at once
	val := randBytes(int(totalSize))
	acc.Set(d, val)
	require.Equal(t, val, acc.Get(d))

	for _, f := range fields {
		fDummy := f.(*dummyField)

		acc := ds.GetField(fDummy.name)
		require.NotNil(t, acc)

		// Check that the field is correctly read
		require.Equal(t, val[fDummy.offset:fDummy.offset+fDummy.size], acc.Get(d))

		// Check that the field is correctly written
		valf := randBytes(int(fDummy.size))
		err = acc.Set(d, valf)
		require.NoError(t, err)
		require.Equal(t, valf, acc.Get(d))
	}
}

func TestDataSourceStaticFieldsTooBig(t *testing.T) {
	t.Parallel()

	ds := New(TypeSingle, "event")

	_, err := ds.AddStaticFields(2, []StaticField{
		&dummyField{
			name:   "f1",
			size:   4,
			offset: 0,
		},
		&dummyField{
			name:   "f2",
			size:   2,
			offset: 4,
		},
	})
	require.Error(t, err)
}

// TODO(Jose): Repeat this for all the types
func TestDataSourceSubscribePriorities(t *testing.T) {
	t.Parallel()

	ds := New(TypeSingle, "event")

	// random list of priorities
	priorities := []int{30, 90, 54, 78, 71, 67, 90, 7, 92, 87}
	called := []int{}

	for _, priority := range priorities {
		priority := priority

		// subscribe saves priority in the called slice
		err := ds.Subscribe(func(fs DataSource, d Data) error {
			called = append(called, priority)
			return nil
		}, priority)
		require.NoError(t, err)
	}

	slices.Sort(priorities)

	// allocate and emit a data
	d, err := ds.NewPacketSingle()
	require.NoError(t, err)
	defer ds.Release(d)

	err = ds.EmitAndRelease(d)
	require.NoError(t, err)

	require.Equal(t, priorities, called)
}

func TestDataSourceSubscribeTypes(t *testing.T) {
	t.Parallel()

	ds := New(TypeSingle, "event")

	err := ds.Subscribe(func(ds DataSource, d Data) error { return nil }, 50)
	require.NoError(t, err)

	err = ds.SubscribeArray(func(ds DataSource, da DataArray) error { return nil }, 50)
	require.Error(t, err)

	err = ds.SubscribePacket(func(ds DataSource, p Packet) error { return nil }, 50)
	require.NoError(t, err)

	ds = New(TypeArray, "events")

	err = ds.Subscribe(func(ds DataSource, d Data) error { return nil }, 50)
	require.NoError(t, err)

	err = ds.SubscribeArray(func(ds DataSource, da DataArray) error { return nil }, 50)
	require.NoError(t, err)

	err = ds.SubscribePacket(func(ds DataSource, p Packet) error { return nil }, 50)
	require.NoError(t, err)
}

func TestDataSourceSubscribeNilCb(t *testing.T) {
	t.Parallel()

	ds := New(TypeSingle, "event")

	err := ds.Subscribe(nil, 50)
	require.Error(t, err)

	err = ds.SubscribeArray(nil, 50)
	require.Error(t, err)

	err = ds.SubscribePacket(nil, 50)
	require.Error(t, err)

	ds = New(TypeArray, "events")

	err = ds.Subscribe(nil, 50)
	require.Error(t, err)

	err = ds.SubscribeArray(nil, 50)
	require.Error(t, err)

	err = ds.SubscribePacket(nil, 50)
	require.Error(t, err)
}

func TestDataSourceNewPacket(t *testing.T) {
	t.Parallel()

	ds := New(TypeSingle, "event")

	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	ds.Release(data)

	dataArray, err := ds.NewPacketArray()
	require.Error(t, err)
	ds.Release(dataArray)

	ds = New(TypeArray, "events")

	data, err = ds.NewPacketSingle()
	require.Error(t, err)
	ds.Release(data)

	dataArray, err = ds.NewPacketArray()
	require.NoError(t, err)
	ds.Release(dataArray)
}

func TestDataSourcePacketArray(t *testing.T) {
	t.Parallel()

	const val = int8(123)

	ds := New(TypeArray, "events")
	acc, err := ds.AddField("foo", api.Kind_Int8)
	require.NoError(t, err)

	pArray, err := ds.NewPacketArray()
	require.NoError(t, err)
	defer ds.Release(pArray)

	require.Equal(t, 0, pArray.Len())

	// It's not possible to add a single packet to an array
	pSingle, err := ds.NewPacketSingle()
	require.Error(t, err)
	ds.Release(pSingle)

	data := pArray.New()

	acc.PutInt8(data, val)

	pArray.Append(data)
	require.Equal(t, 1, pArray.Len())

	getData := pArray.Get(0)
	require.NotNil(t, getData)

	require.Equal(t, val, acc.Int8(getData))
}

func TestDataSourceSubscribeSingle(t *testing.T) {
	t.Parallel()

	const value = int8(123)

	ds := New(TypeSingle, "event")

	acc, err := ds.AddField("foo", api.Kind_Int8)
	require.NoError(t, err)

	pSingle, err := ds.NewPacketSingle()
	require.NoError(t, err)
	defer ds.Release(pSingle)

	acc.PutInt8(pSingle, value)

	// Subscribe to the single data
	var valueFromData int8
	err = ds.Subscribe(func(fs DataSource, d Data) error {
		valueFromData = acc.Int8(d)
		return nil
	}, 50)
	require.NoError(t, err)

	// Subscribe to the packet
	var valuesFromPacket int8
	err = ds.SubscribePacket(func(fs DataSource, p Packet) error {
		// We know that the packet is a PacketSingle because the ds is TypeArray
		valuesFromPacket = acc.Int8(p.(PacketSingle))
		return nil
	}, 50)
	require.NoError(t, err)

	// Emit the packet
	err = ds.EmitAndRelease(pSingle)
	require.NoError(t, err)

	// Check that all the callbacks received the same value
	require.Equal(t, value, valueFromData)
	require.Equal(t, value, valuesFromPacket)
}

func TestDataSourceSubscribeArray(t *testing.T) {
	t.Parallel()

	ds := New(TypeArray, "events")

	pArray, err := ds.NewPacketArray()
	require.NoError(t, err)
	defer ds.Release(pArray)

	acc, err := ds.AddField("foo", api.Kind_Int8)
	require.NoError(t, err)

	// Add some values to the array
	values := []int8{30, 54, 90}
	for _, val := range values {
		data := pArray.New()
		acc.PutInt8(data, val)
		pArray.Append(data)
	}

	// Subscribe to the single data
	valuesFromData := []int8{}
	err = ds.Subscribe(func(fs DataSource, d Data) error {
		valuesFromData = append(valuesFromData, acc.Int8(d))
		return nil
	}, 50)
	require.NoError(t, err)

	// Subscribe to the array
	valuesFromArray := []int8{}
	err = ds.SubscribeArray(func(fs DataSource, da DataArray) error {
		for i := 0; i < da.Len(); i++ {
			valuesFromArray = append(valuesFromArray, acc.Int8(da.Get(i)))
		}
		return nil
	}, 50)
	require.NoError(t, err)

	// Subscribe to the packet
	valuesFromPacket := []int8{}
	err = ds.SubscribePacket(func(fs DataSource, p Packet) error {
		// We know that the packet is a PacketArray because the ds is TypeArray
		pa := p.(PacketArray)
		for i := 0; i < pa.Len(); i++ {
			valuesFromPacket = append(valuesFromPacket, acc.Int8(pa.Get(i)))
		}
		return nil
	}, 50)
	require.NoError(t, err)

	// Emit the packet
	err = ds.EmitAndRelease(pArray)
	require.NoError(t, err)

	// Check that all the callbacks received the same values
	require.Equal(t, values, valuesFromData)
	require.Equal(t, values, valuesFromArray)
	require.Equal(t, values, valuesFromPacket)
}

type dummyField struct {
	name   string
	size   uint32
	offset uint32
}

func (d *dummyField) FieldName() string {
	return d.name
}

func (d *dummyField) FieldSize() uint32 {
	return d.size
}

func (d *dummyField) FieldOffset() uint32 {
	return d.offset
}

func randBytes(n int) []byte {
	ret := make([]byte, n)
	rand.Read(ret)
	return ret
}
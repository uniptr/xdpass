package tlv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"unsafe"
)

type TLV struct {
	Type   uint16
	Length uint16
}

// Type(2) + Length(2)
const tlvHdrLen = 4

func (t *TLV) Len() int {
	return tlvHdrLen + int(t.Length)
}

func (t *TLV) decodeHeader(r io.Reader) error {
	var x uint32
	h := (*[tlvHdrLen]byte)(unsafe.Pointer(&x))

	_, err := io.ReadFull(r, h[:])
	if err != nil {
		return err
	}

	t.Type = binary.BigEndian.Uint16(h[:2])
	t.Length = binary.BigEndian.Uint16(h[2:4])

	return nil
}

func (t *TLV) DecodeFrom(r io.Reader) ([]byte, error) {
	err := t.decodeHeader(r)
	if err != nil {
		return nil, err
	}

	value := make([]byte, t.Length)
	_, err = io.ReadFull(r, value)
	return value, err
}

func (t *TLV) Decode(data []byte) ([]byte, error) {
	if len(data) < tlvHdrLen {
		return nil, errors.New("data less than TLV header length")
	}

	b := bytes.NewBuffer(data)
	err := t.decodeHeader(b)
	if err != nil {
		return nil, err
	}

	if len(data) < t.Len() {
		return nil, errors.New("data less than TLV length")
	}

	return data[tlvHdrLen:t.Len()], nil
}

func (t *TLV) EncodeTo(w io.Writer, value []byte) (int, error) {
	var x uint32
	h := (*[tlvHdrLen]byte)(unsafe.Pointer(&x))

	binary.BigEndian.PutUint16(h[:2], uint16(t.Type))
	binary.BigEndian.PutUint16(h[2:4], uint16(t.Length))

	nh, err := w.Write(h[:])
	if err != nil {
		return nh, err
	}

	nv, err := w.Write(value)
	return nh + nv, err
}

func (t *TLV) Encode(value []byte) ([]byte, error) {
	b := bytes.NewBuffer(make([]byte, 0, tlvHdrLen+len(value)))
	_, err := t.EncodeTo(b, value)
	return b.Bytes(), err
}

func DecodeFrom(r io.Reader) ([]byte, error) {
	var v TLV
	return v.DecodeFrom(r)
}

func EncodeTo(w io.Writer, value []byte) (int, error) {
	v := TLV{Length: uint16(len(value))}
	return v.EncodeTo(w, value)
}

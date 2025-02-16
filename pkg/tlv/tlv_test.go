package tlv

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLV_Len(t *testing.T) {
	tlv := TLV{Type: 1, Length: 3}
	expectedLen := tlvHdrLen + 3 // 4 + 3
	assert.Equal(t, expectedLen, tlv.Len(), "Expected length should match the calculated length")
}

func TestTLV_DecodeFrom(t *testing.T) {
	data := []byte{0x00, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03} // Type=1, Length=3, Value=[1,2,3]
	tlv := TLV{}
	buf := bytes.NewBuffer(data)

	value, err := tlv.DecodeFrom(buf)
	assert.NoError(t, err, "Decoding from buffer should not result in an error")

	expectedValue := []byte{0x01, 0x02, 0x03}
	assert.Equal(t, expectedValue, value, "Decoded value should match the expected value")
}

func TestTLV_Decode(t *testing.T) {
	data := []byte{0x00, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03} // Type=1, Length=3, Value=[1,2,3]
	tlv := TLV{}

	value, err := tlv.Decode(data)
	assert.NoError(t, err, "Decoding should not result in an error")

	expectedValue := []byte{0x01, 0x02, 0x03}
	assert.Equal(t, expectedValue, value, "Decoded value should match the expected value")
}

func TestTLV_EncodeTo(t *testing.T) {
	tlv := TLV{Type: 1, Length: 3}
	value := []byte{0x01, 0x02, 0x03}

	var buf bytes.Buffer
	n, err := tlv.EncodeTo(&buf, value)
	require.NoError(t, err, "Writing to buffer should not result in an error")
	require.Equal(t, n, len(value)+tlvHdrLen, "Number of bytes written should match the total length")

	expectedData := []byte{0x00, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03}
	assert.Equal(t, expectedData, buf.Bytes(), "Written bytes should match the expected data")
}

func TestTLV_Encode(t *testing.T) {
	tlv := TLV{Type: 1, Length: 3}
	value := []byte{0x01, 0x02, 0x03}

	encodedData, err := tlv.Encode(value)
	require.NoError(t, err, "Encoding should not result in an error")

	expectedData := []byte{0x00, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03}
	assert.Equal(t, expectedData, encodedData, "Encoded data should match the expected data")
}

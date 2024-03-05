package model

//
// Packet
//
// Parsing and serializing OpenVPN packets.
//

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/ooni/minivpn/internal/bytesx"
	"github.com/ooni/minivpn/internal/runtimex"
)

// Opcode is an OpenVPN packet opcode.
type Opcode byte

// OpenVPN packets opcodes.
const (
	P_CONTROL_HARD_RESET_CLIENT_V1 = Opcode(iota + 1) // 1
	P_CONTROL_HARD_RESET_SERVER_V1                    // 2
	P_CONTROL_SOFT_RESET_V1                           // 3
	P_CONTROL_V1                                      // 4
	P_ACK_V1                                          // 5
	P_DATA_V1                                         // 6
	P_CONTROL_HARD_RESET_CLIENT_V2                    // 7
	P_CONTROL_HARD_RESET_SERVER_V2                    // 8
	P_DATA_V2                                         // 9
)

// NewOpcodeFromString returns an opcode from a string representation, and an error if it cannot parse the opcode
// representation. The zero return value is invalid and always coupled with a non-nil error.
func NewOpcodeFromString(s string) (Opcode, error) {
	switch s {
	case "CONTROL_HARD_RESET_CLIENT_V1":
		return P_CONTROL_HARD_RESET_CLIENT_V1, nil
	case "CONTROL_HARD_RESET_SERVER_V1":
		return P_CONTROL_HARD_RESET_SERVER_V1, nil
	case "CONTROL_SOFT_RESET_V1":
		return P_CONTROL_SOFT_RESET_V1, nil
	case "CONTROL_V1":
		return P_CONTROL_V1, nil
	case "ACK_V1":
		return P_ACK_V1, nil
	case "DATA_V1":
		return P_DATA_V1, nil
	case "CONTROL_HARD_RESET_CLIENT_V2":
		return P_CONTROL_HARD_RESET_CLIENT_V2, nil
	case "CONTROL_HARD_RESET_SERVER_V2":
		return P_CONTROL_HARD_RESET_SERVER_V2, nil
	case "DATA_V2":
		return P_DATA_V2, nil
	default:
		return 0, errors.New("unknown opcode")
	}
}

// String returns the opcode string representation
func (op Opcode) String() string {
	switch op {
	case P_CONTROL_HARD_RESET_CLIENT_V1:
		return "P_CONTROL_HARD_RESET_CLIENT_V1"

	case P_CONTROL_HARD_RESET_SERVER_V1:
		return "P_CONTROL_HARD_RESET_SERVER_V1"

	case P_CONTROL_SOFT_RESET_V1:
		return "P_CONTROL_SOFT_RESET_V1"

	case P_CONTROL_V1:
		return "P_CONTROL_V1"

	case P_ACK_V1:
		return "P_ACK_V1"

	case P_DATA_V1:
		return "P_DATA_V1"

	case P_CONTROL_HARD_RESET_CLIENT_V2:
		return "P_CONTROL_HARD_RESET_CLIENT_V2"

	case P_CONTROL_HARD_RESET_SERVER_V2:
		return "P_CONTROL_HARD_RESET_SERVER_V2"

	case P_DATA_V2:
		return "P_DATA_V2"

	default:
		return "P_UNKNOWN"
	}
}

// IsControl returns true when this opcode is a control opcode.
func (op Opcode) IsControl() bool {
	switch op {
	case P_CONTROL_HARD_RESET_CLIENT_V1,
		P_CONTROL_HARD_RESET_SERVER_V1,
		P_CONTROL_SOFT_RESET_V1,
		P_CONTROL_V1,
		P_CONTROL_HARD_RESET_CLIENT_V2,
		P_CONTROL_HARD_RESET_SERVER_V2:
		return true
	default:
		return false
	}
}

// IsData returns true when this opcode is a data opcode.
func (op Opcode) IsData() bool {
	switch op {
	case P_DATA_V1, P_DATA_V2:
		return true
	default:
		return false
	}
}

// SessionID is the session identifier.
type SessionID [8]byte

// PacketID is a packet identifier.
type PacketID uint32

// PeerID is the type of the P_DATA_V2 peer ID.
type PeerID [3]byte

// Packet is an OpenVPN packet.
type Packet struct {
	// Opcode is the packet message type (a P_* constant; high 5-bits of
	// the first packet byte).
	Opcode Opcode

	// The key_id refers to an already negotiated TLS session.
	// This is the shortened version of the key-id (low 3-bits of the first
	// packet byte).
	KeyID byte

	// PeerID is the peer ID.
	PeerID PeerID

	// LocalSessionID is the local session ID.
	LocalSessionID SessionID

	// Acks contains the remote packets we're ACKing.
	ACKs []PacketID

	// RemoteSessionID is the remote session ID.
	RemoteSessionID SessionID

	// ID is the packet-id for replay protection. According to the spec: "4 or 8 bytes,
	// includes sequence number and optional time_t timestamp".
	//
	// This library does not use the timestamp.
	// TODO(ainghazal): use optional.Value (only control packets have packet id)
	ID PacketID

	// Payload is the packet's payload.
	Payload []byte

	// TLSAuth marks whether to use control packet authentication (tls-auth)
	TLSAuth bool

	// tlsAuthKey is the key used for tls-auth.
	tlsAuthKey []byte

	once sync.Once
}

// SetTLSAuthKey sets the key used for TLS Authentication.
func (p *Packet) SetTLSAuthKey(key []byte) {
	p.once.Do(func() {
		p.tlsAuthKey = key
	})
}

// ErrPacketTooShort indicates that a packet is too short.
var ErrPacketTooShort = errors.New("openvpn: packet too short")

// ParsePacket produces a packet after parsing the common header. We assume that
// the underlying connection has already stripped out the framing.
// If the tlsAuth parameter is true, we will attempt to authenticate the HMAC.
// TODO(ainghazal): parse authConfig struct around with key
func ParsePacket(buf []byte, tlsAuth bool) (*Packet, error) {
	// a valid packet is larger, but this allows us
	// to keep parsing a non-data packet.
	if len(buf) < 2 {
		return nil, ErrPacketTooShort
	}

	// parsing opcode and keyID
	opcode := Opcode(buf[0] >> 3)
	keyID := buf[0] & 0x07

	// extract the packet payload and possibly the peerID
	var (
		payload []byte
		peerID  PeerID
	)
	switch opcode {
	case P_DATA_V2:
		if len(buf) < 4 {
			return nil, ErrPacketTooShort
		}
		copy(peerID[:], buf[1:4])
		payload = buf[4:]
	default:
		payload = buf[1:]
	}

	// ACKs and control packets require more complex parsing
	if opcode.IsControl() || opcode == P_ACK_V1 {
		return parseControlOrACKPacket(opcode, keyID, payload, tlsAuth)
	}

	// otherwise just return the data packet.
	p := &Packet{
		Opcode:          opcode,
		KeyID:           keyID,
		PeerID:          peerID,
		LocalSessionID:  [8]byte{},
		ACKs:            []PacketID{},
		RemoteSessionID: [8]byte{},
		ID:              0,
		Payload:         payload,
		once:            sync.Once{},
	}
	return p, nil
}

// NewPacket returns a packet from the passed arguments: opcode, keyID and a raw payload.
func NewPacket(opcode Opcode, keyID uint8, payload []byte) *Packet {
	return &Packet{
		Opcode:          opcode,
		KeyID:           keyID,
		PeerID:          [3]byte{},
		LocalSessionID:  [8]byte{},
		ACKs:            []PacketID{},
		RemoteSessionID: [8]byte{},
		ID:              0,
		Payload:         payload,
	}
}

// ErrEmptyPayload indicates tha the payload of an OpenVPN control packet is empty.
var ErrEmptyPayload = errors.New("openvpn: empty payload")

// ErrParsePacket is a generic packet parse error which may be further qualified.
var ErrParsePacket = errors.New("openvpn: packet parse error")

// parseControlOrACKPacket parses the contents of a control or ACK packet.
func parseControlOrACKPacket(opcode Opcode, keyID byte, payload []byte, tlsAuth bool) (*Packet, error) {
	// make sure we have payload to parse and we're parsing control or ACK
	if len(payload) <= 0 {
		return nil, ErrEmptyPayload
	}
	if !opcode.IsControl() && opcode != P_ACK_V1 {
		return nil, fmt.Errorf("%w: %s", ErrParsePacket, "expected control/ack packet")
	}

	// create a buffer for parsing the packet
	buf := bytes.NewBuffer(payload)

	p := NewPacket(opcode, keyID, payload)

	// local session id
	if _, err := io.ReadFull(buf, p.LocalSessionID[:]); err != nil {
		return p, fmt.Errorf("%w: bad sessionID: %s", ErrParsePacket, err)
	}

	if tlsAuth {
		// TODO: factor out common code with case below --------------
		packetHMAC := make([]byte, 64)
		_, err := buf.Read(packetHMAC)
		if err != nil {
			return p, fmt.Errorf("%w: cannot parse HMAC: %s", ErrParsePacket, err)
		}

		// TODO(ainghazal): calculate HMAC and abort if it does not match.
		fmt.Printf("HMAC: %x\n", packetHMAC)

		val, err := bytesx.ReadUint32(buf)
		if err != nil {
			return p, fmt.Errorf("%w: bad packetID: %s", ErrParsePacket, err)
		}
		p.ID = PacketID(val)

		netTime := make([]byte, 4)
		_, err = buf.Read(netTime)
		if err != nil {
			return p, fmt.Errorf("%w: cannot parse net time: %s", ErrParsePacket, err)
		}

		ackArrayLenByte, err := buf.ReadByte()
		if err != nil {
			return p, fmt.Errorf("%w: bad ack: %s", ErrParsePacket, err)
		}
		ackArrayLen := int(ackArrayLenByte)

		// ack array
		p.ACKs = make([]PacketID, ackArrayLen)
		for i := 0; i < ackArrayLen; i++ {
			val, err := bytesx.ReadUint32(buf)
			if err != nil {
				return p, fmt.Errorf("%w: cannot parse ack id: %s", ErrParsePacket, err)
			}
			p.ACKs[i] = PacketID(val)
		}

		// remote session id
		if ackArrayLen > 0 {
			if _, err = io.ReadFull(buf, p.RemoteSessionID[:]); err != nil {
				return p, fmt.Errorf("%w: bad remote sessionID: %s", ErrParsePacket, err)
			}
		}

		if p.Opcode != P_ACK_V1 {
			val, err := bytesx.ReadUint32(buf)
			if err != nil {
				return p, fmt.Errorf("%w: bad packetID: %s", ErrParsePacket, err)
			}
			p.ID = PacketID(val)
		}

	} else {

		// ack array length
		ackArrayLenByte, err := buf.ReadByte()
		if err != nil {
			return p, fmt.Errorf("%w: bad ack: %s", ErrParsePacket, err)
		}
		ackArrayLen := int(ackArrayLenByte)

		// ack array
		p.ACKs = make([]PacketID, ackArrayLen)
		for i := 0; i < ackArrayLen; i++ {
			val, err := bytesx.ReadUint32(buf)
			if err != nil {
				return p, fmt.Errorf("%w: cannot parse ack id: %s", ErrParsePacket, err)
			}
			p.ACKs[i] = PacketID(val)
		}

		// remote session id
		if ackArrayLen > 0 {
			if _, err = io.ReadFull(buf, p.RemoteSessionID[:]); err != nil {
				return p, fmt.Errorf("%w: bad remote sessionID: %s", ErrParsePacket, err)
			}
		}

		// packet id
		if p.Opcode != P_ACK_V1 {
			val, err := bytesx.ReadUint32(buf)
			if err != nil {
				return p, fmt.Errorf("%w: bad packetID: %s", ErrParsePacket, err)
			}
			p.ID = PacketID(val)
			fmt.Println("PACKET ID =>", p.ID)
		}

	}

	// payload
	p.Payload = buf.Bytes()
	return p, nil
}

// ErrMarshalPacket is the error returned when we cannot marshal a packet.
var ErrMarshalPacket = errors.New("cannot marshal packet")

//	TODO(ainghazal): HMAC is broken in packets we send.
//
// controlPacketHeader writes the following information to the returned buffer:
//
//   - ??? : packet-id for replay protection (4 or 8 bytes, includes
//     sequence number and optional time_t timestamp).
//   - P_ACK packet_id array length (1 byte).
//   - P_ACK packet-id array (if length > 0).
//   - P_ACK remote session_id (if length > 0).
//   - message packet-id (4 bytes).
func (p *Packet) controlPacketHeader(t time.Time) ([]byte, error) {
	buf := &bytes.Buffer{}

	// we write a byte with the number of acks, and then serialize each ack.
	nAcks := len(p.ACKs)
	if nAcks > math.MaxUint8 {
		return []byte{}, fmt.Errorf("too many ACKs")
	}
	buf.WriteByte(byte(nAcks))
	for i := 0; i < nAcks; i++ {
		bytesx.WriteUint32(buf, uint32(p.ACKs[i]))
	}

	// remote session id
	if len(p.ACKs) > 0 {
		buf.Write(p.RemoteSessionID[:])
	}
	if p.Opcode != P_ACK_V1 {
		bytesx.WriteUint32(buf, uint32(p.ID))
	}
	return buf.Bytes(), nil
}

// authenticateControlPacket returns the HMAC of the control packet encapsulation header.
func (p *Packet) authenticateControlPacket(l3 []byte, header []byte) []byte {
	// TODO(ainghazal): get the hmac function (on packet constructor, sha512 is hardcoded)
	// TODO(ainghazal): honor key direction. But is the key direction being properly honored by OpenVPN??

	runtimex.Assert(len(p.tlsAuthKey) != 0, "tls auth key not initialized")
	buf := &bytes.Buffer{}

	// First, write L3 to the HMAC buffer
	buf.Write(l3)

	// Second,write L1 (opcode composite + packet session id)
	// where L1 = [OP] + [PSID]
	buf.WriteByte((byte(p.Opcode) << 3) | (p.KeyID & 0x07))
	buf.Write(p.LocalSessionID[:])

	// Third, write the rest of data to be authenticated
	buf.Write(header)
	buf.Write(p.Payload)

	// we use the last 64 bytes from the static key to authenticate outgoing packets.
	hmacKey := p.tlsAuthKey[len(p.tlsAuthKey)-64:]
	hmacHash := hmac.New(sha512.New, hmacKey)
	hmacHash.Write(buf.Bytes())
	return hmacHash.Sum(nil)
}

// Bytes returns a byte array that is ready to be sent on the wire.
func (p *Packet) Bytes() ([]byte, error) {
	buf := &bytes.Buffer{}

	switch p.Opcode {
	case P_DATA_V2:
		// we assume this is an encrypted data packet,
		// so we serialize just the encrypted payload

	default:
		buf.WriteByte((byte(p.Opcode) << 3) | (p.KeyID & 0x07))
		buf.Write(p.LocalSessionID[:])

		ts := time.Now()

		hdr, err := p.controlPacketHeader(ts)
		if err != nil {
			return []byte{}, fmt.Errorf("%w: err", ErrMarshalPacket)
		}
		if p.TLSAuth {
			l3 := &bytes.Buffer{}
			// L3 is the packet ID + timestamp
			bytesx.WriteUint32(l3, uint32(p.ID+1))
			bytesx.WriteUint32(l3, uint32(ts.Unix()))

			// authenticate the packet ID preamble and the rest of the packet header
			// plus any packet payload.
			auth := p.authenticateControlPacket(l3.Bytes(), hdr)

			// the HMAC comes after L1
			// [L1=OP+PSID] [L2=HMAC] [L3=PID+...]
			buf.Write(auth)
			buf.Write(l3.Bytes())
		}
		buf.Write(hdr)
	}
	//  payload
	buf.Write(p.Payload)

	return buf.Bytes(), nil
}

// IsControl returns true if the packet is any of the control types.
func (p *Packet) IsControl() bool {
	return p.Opcode.IsControl()
}

// IsData returns true if the packet is of data type.
func (p *Packet) IsData() bool {
	return p.Opcode.IsData()
}

var pingPayload = []byte{0x2A, 0x18, 0x7B, 0xF3, 0x64, 0x1E, 0xB4, 0xCB, 0x07, 0xED, 0x2D, 0x0A, 0x98, 0x1F, 0xC7, 0x48}

func (p *Packet) IsPing() bool {
	return bytes.Equal(pingPayload, p.Payload)
}

// Log writes an entry in the passed logger with a representation of this packet.
func (p *Packet) Log(logger Logger, direction Direction) {
	var dir string
	switch direction {
	case DirectionIncoming:
		dir = "<"
	case DirectionOutgoing:
		dir = ">"
	default:
		logger.Warnf("wrong direction: %d", direction)
		return
	}

	logger.Debugf(
		"%s %s {id=%d, acks=%v} localID=%x remoteID=%x [%d bytes]",
		dir,
		p.Opcode,
		p.ID,
		p.ACKs,
		p.LocalSessionID,
		p.RemoteSessionID,
		len(p.Payload),
	)
}

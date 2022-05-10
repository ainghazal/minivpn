package vpn

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
)

//
// OpenVPN Multiplexer
//

/*

 From: https://community.openvpn.net/openvpn/wiki/SecurityOverview

 OpenVPN multiplexes the SSL/TLS session used for authentication and key
 exchange with the actual encrypted tunnel data stream. OpenVPN provides the
 SSL/TLS connection with a reliable transport layer (as it is designed to
 operate over). The actual IP packets, after being encrypted and signed with an
 HMAC, are tunnelled over UDP without any reliability layer. So if --proto udp
 is used, no IP packets are tunneled over a reliable transport, eliminating the
 problem of reliability-layer collisions -- Of course, if you are tunneling a
 TCP session over OpenVPN running in UDP mode, the TCP protocol itself will
 provide the reliability layer.

SSL/TLS -> Reliability Layer -> \
           --tls-auth HMAC       \
                                  \
                                   > Multiplexer ----> UDP
                                  /                    Transport
IP        Encrypt and HMAC       /
Tunnel -> using OpenSSL EVP --> /
Packets   interface.

This model has the benefit that SSL/TLS sees a reliable transport layer while
the IP packet forwarder sees an unreliable transport layer -- exactly what both
components want to see. The reliability and authentication layers are
completely independent of one another, i.e. the sequence number is embedded
inside the HMAC-signed envelope and is not used for authentication purposes.
*/

// muxer is the VPN transport multiplexer. The muxer:
// 1. is given access to the transport net.Conn (it owns it).
// 2. reads from the transport
// 3. holds references to a controler and a dataHandler implementer.
// 4. initializes and owns a session instance.
// 5. on reads, it routes data packets to the dataHandler implementer, and
//    control packets to the controler implementor.
type muxer struct {
	// a net.Conn that has access to the "wire" transport. this can represent
	// an UDP/TCP socket, or a net.Conn coming from a Pluggable Transport etc.
	conn net.Conn
	tls  net.Conn

	control   controlHandler
	data      dataHandler
	bufReader *bytes.Buffer

	session *session
	tunnel  *tunnel
}

// controlHandler manages the control "channel".
type controlHandler interface {
	Options() *Options
	InitTLS(net.Conn, *session) (net.Conn, error)
	SendHardReset(net.Conn, *session)
	// ...
}

// dataHandler manages the data "channel".
type dataHandler interface {
	SetupKeys(*dataChannelKey, *session) error
	WritePacket(net.Conn, []byte) (int, error)
	ReadPacket(*packet) ([]byte, error)
}

// initialization

func newMuxerFromOptions(conn net.Conn, opt *Options) (*muxer, error) {
	br := bytes.NewBuffer(nil)
	control := newControl(opt)
	session, err := newSession()
	if err != nil {
		return &muxer{}, err
	}
	data, err := newDataFromOptions(opt, session)
	if err != nil {
		return &muxer{}, err
	}
	m := &muxer{
		conn:      conn,
		session:   session,
		control:   control,
		data:      data,
		bufReader: br,
	}
	return m, nil
}

// handshake

func (m *muxer) Handshake() error {
	// 1. control channel sends reset, parse response.
	if err := m.Reset(); err != nil {
		return err
	}

	// 2. tls handshake.
	tls, err := m.control.InitTLS(m.conn, m.session)
	if err != nil {
		return err
	}
	m.tls = tls

	// 3. data channel init (auth, push, data initialization).
	if err := m.InitDataWithRemoteKey(); err != nil {
		return err
	}

	log.Println("VPN handshake done.")
	return nil
}

// Reset sends a hard-reset packet to the server, and waits for the server
// confirmation. It is the third step in an OpenVPN connection (out of five).
func (m *muxer) Reset() error {
	m.control.SendHardReset(m.conn, m.session)
	resp := m.readPacket()

	remoteSessionID, err := parseHardReset(resp)
	// here we could check if we have received a remote session id but
	// our session.remoteSessionID is != from all zeros
	if err != nil {
		return fmt.Errorf("%s: %w", ErrBadHandshake, err)
	}
	m.session.RemoteSessionID = remoteSessionID
	log.Printf("Learned remote session ID: %x\n", remoteSessionID.Bytes())

	// we assume id is 0, this is the first packet we ack.
	// TODO should I parse the real packet id from server instead? this might be important when re-keying...
	sendACK(m.conn, m.session, uint32(0))
	return nil
}

// direct read

// TODO return error too
func (m *muxer) readPacket() []byte {
	switch m.conn.LocalAddr().Network() {
	case protoTCP.String():
		buf, err := readPacketFromTCP(m.conn)
		if err != nil {
			return nil
		}
		return buf
	default:
		// for UDP we don't need to parse size frames
		buf, err := readPacketFromUDP(m.conn)
		if err != nil {
			return nil
		}
		return buf
	}
}

func readPacketFromUDP(conn net.Conn) ([]byte, error) {
	const enough = 1 << 17
	buf := make([]byte, enough)
	count, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	buf = buf[:count]
	return buf, nil
}

func readPacketFromTCP(conn net.Conn) ([]byte, error) {
	lenbuff := make([]byte, 2)

	if _, err := io.ReadFull(conn, lenbuff); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenbuff)
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// read-and-handle packets

// handleIncoming packet reads the next packet available in the underlying
// socket. It returns true if the packet was a data packet; otherwise it will
// process it but return false.
func (m *muxer) handleIncomingPacket() bool {
	data := m.readPacket()
	p := newPacketFromBytes(data)
	if p.isACK() {
		log.Println("Got ACK")
		return false
	}
	if p.isControl() {
		log.Println("Got control packet", len(data))
		// TODO pass it to contronHandler.
		// Here the server might be requesting us to reset, or to
		// re-key (but I keep ignoring that case for now).
		fmt.Println(hex.Dump(p.payload))
		return false
	}
	if !p.isData() {
		log.Printf("ERROR: unhandled data. (op: %d)\n", p.opcode)
		fmt.Println(hex.Dump(data))
		return false
	}
	if isPingPacket(data) {
		m.handleDataPing()
		return false
	}
	// at this point, the incoming packet should be data that needs to be processed
	// (decompress+decrypt)

	// TODO pass the packet itself
	//plaintext, err := m.data.ReadPacket(data)
	plaintext, err := m.data.ReadPacket(p)
	if err != nil {
		log.Println("bad decryption:", err.Error())
		// XXX I'm not sure returning false is the right thing to do here.
		return false
	}

	// all good! we write the plaintext into the buffer.
	// the caller is responsible for reading from there.
	m.bufReader.Write(plaintext)
	return true
}

func (m *muxer) handleDataPing() error {
	log.Println("openvpn-ping, sending reply")
	m.data.WritePacket(m.conn, pingPayload)
	return nil
}

// tls channel reads

func (m *muxer) readTLSPacket() ([]byte, error) {
	data := make([]byte, 4096)
	_, err := m.tls.Read(data)
	return data, err
}

func (m *muxer) readAndLoadRemoteKey() error {
	data, err := m.readTLSPacket()
	if err != nil {
		return err
	}
	if !isControlMessage(data) {
		return fmt.Errorf("%w:%s", errBadControlMessage, "expected null header")
	}
	remoteKey, opts, err := readControlMessage(data)
	if err != nil {
		// TODO proper error
		log.Println("ERROR: cannot parse control message")
	}
	key, err := m.session.ActiveKey()
	if err != nil {
		// TODO proper error
		log.Println("ERROR: cannot get active key", err.Error())
		return err
	}
	key.addRemoteKey(remoteKey)
	tunnel, err := parseRemoteOptions(opts)
	if err != nil {
		return err
	}
	m.tunnel = tunnel
	return nil
}

func (m *muxer) readPushReply() error {
	reply, err := m.readTLSPacket()
	if err != nil {
		return err
	}

	if isBadAuthReply(reply) {
		return errBadAuth
	}

	if !isPushReply(reply) {
		return fmt.Errorf("%w:%s", errBadServerReply, "expected push reply")
	}

	ip := parsePushedOptions(reply)
	m.tunnel.ip = ip
	return nil
}

//
// write methods
//

// tls writes

// ---------------------------------------------------------------------------------------------------
// TODO: refactor: turn into a method in controlHandler or bring the other control write methods here.
// ---------------------------------------------------------------------------------------------------

func (m *muxer) sendPushRequest() {
	m.tls.Write(encodePushRequestAsBytes())
}

// InitDataWithRemoteKey initializes the internal data channel. To do that, it sends a
// control packet, parses the response, and derives the cryptographic material
// that will be used to encrypt and decrypt data through the tunnel. At the end
// of this exchange, the data channel is ready to be used.
func (m *muxer) InitDataWithRemoteKey() error {
	// 1. first we need to send a control message
	controlMessage, err := encodeControlMessage(m.session, m.control.Options())
	if _, err := m.tls.Write(controlMessage); err != nil {
		return err
	}

	// 2. then we read the server response and load the remote key
	err = m.readAndLoadRemoteKey()
	if err != nil {
		return err
	}
	log.Println("Key exchange complete")

	// 3. now we can initialize the data channel.

	key0, err := m.session.ActiveKey()
	if err != nil {
		return err
	}

	err = m.data.SetupKeys(key0, m.session)
	if err != nil {
		return err
	}

	// 4. finally, we ask the server to push remote options to us. we parse
	// them and keep some useful info.
	m.sendPushRequest()
	m.readPushReply()

	log.Println("Data channel initialized.")
	return nil
}

// TODO(ainghazal, bassosimone): it probably makes sense to return an error
// from read/write if the data channel is not initialized. Another option would
// be to read from a channel and block if there's nothing.

// Write sends bytes as encrypted packets in the data channel.
func (m *muxer) Write(b []byte) (int, error) {
	return m.data.WritePacket(m.conn, b)
}

// Read reads bytes after decrypting packets from the data channel.
func (m *muxer) Read(b []byte) (int, error) {
	for {
		if ok := m.handleIncomingPacket(); ok {
			break
		}
	}
	return m.bufReader.Read(b)
}

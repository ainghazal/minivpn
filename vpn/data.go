package vpn

//
// OpenVPN data channel
//

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"net"
	"strings"
	"sync"
)

var (
	errDataChannelKey = errors.New("bad key")
	errBadCompression = errors.New("bad compression")
	errReplayAttack   = errors.New("replay attack")
	errCannotEncrypt  = errors.New("cannot encrypt")
	errCannotDecrypt  = errors.New("cannot decrypt")
	errBadHMAC        = errors.New("bad hmac")
	errInitError      = errors.New("improperly initialized")
)

// keySlot holds the different local and remote keys.
type keySlot [64]byte

// dataChannelState is the state of the data channel.
type dataChannelState struct {
	dataCipher      dataCipher
	hmac            func() hash.Hash
	hmacSize        uint8
	remotePacketID  packetID
	cipherKeyLocal  keySlot
	cipherKeyRemote keySlot
	hmacKeyLocal    keySlot
	hmacKeyRemote   keySlot

	mu sync.Mutex
}

// SetSetRemotePacketID stores the passed packetID internally.
func (dcs *dataChannelState) SetRemotePacketID(id packetID) {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	dcs.remotePacketID = packetID(id)
}

// RemotePacketID returns the last known remote packetID. It returns an error
// if the stored packet id has reached the maximum capacity of the packetID
// type.
func (dcs *dataChannelState) RemotePacketID() (packetID, error) {
	dcs.mu.Lock()
	defer dcs.mu.Unlock()
	pid := dcs.remotePacketID
	if pid == math.MaxUint32 {
		// we reached the max packetID, increment will overflow
		return 0, errExpiredKey
	}
	return pid, nil
}

// dataChannelKey represents a pair of key sources that have been negotiated
// over the control channel, and from which we will derive local and remote
// keys for encryption and decrption over the data channel. The index refers to
// the short key_id that is passed in the lower 3 bits if a packet header.
// The setup of the keys for a given data channel (that is, for every key_id)
// is made by expanding the keysources using the prf function.
// Do note that we are not yet implementing key renegotiation - but the index
// is provided for convenience when/if we support that in the future.
type dataChannelKey struct {
	index  uint32
	ready  bool
	local  *keySource
	remote *keySource
	mu     sync.Mutex
}

// addRemoteKey adds the server keySource to our dataChannelKey. This makes the
// dataChannelKey ready to be used.
func (dck *dataChannelKey) addRemoteKey(k *keySource) error {
	dck.mu.Lock()
	defer dck.mu.Unlock()
	if dck.ready {
		return fmt.Errorf("%w:%s", errDataChannelKey, "cannot overwrite remote key slot")
	}
	dck.remote = k
	dck.ready = true
	return nil
}

var (
	randomFn       = genRandomBytes
	errRandomBytes = errors.New("Error generating random bytes")
)

// keySource contains random data to generate keys.
type keySource struct {
	r1        [32]byte
	r2        [32]byte
	preMaster [48]byte
}

// Bytes returns the byte representation of a keySource.
func (k *keySource) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(k.preMaster[:])
	buf.Write(k.r1[:])
	buf.Write(k.r2[:])
	return buf.Bytes()
}

// newKeySource returns a keySource and an error.
func newKeySource() (*keySource, error) {
	random1, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}

	var r1, r2 [32]byte
	var preMaster [48]byte
	copy(r1[:], random1)

	random2, err := randomFn(32)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	copy(r2[:], random2)

	random3, err := randomFn(48)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errRandomBytes, err.Error())
	}
	copy(preMaster[:], random3)
	return &keySource{
		r1:        r1,
		r2:        r2,
		preMaster: preMaster,
	}, nil
}

// data represents the data "channel", that will encrypt and decrypt the tunnel payloads.
// data implements the dataHandler interface.
type data struct {
	options         *Options
	session         *session
	state           *dataChannelState
	decodeFn        func([]byte, *dataChannelState) (*encryptedData, error)
	encryptEncodeFn func([]byte, *session, *dataChannelState) ([]byte, error)
	decryptFn       func([]byte, *encryptedData) ([]byte, error)
}

var _ dataHandler = &data{} // Ensure that we implement dataHandler

// newDataFromOptions returns a new data object, initialized with the
// options given. it also returns any error raised.
func newDataFromOptions(opt *Options, s *session) (*data, error) {
	if opt == nil || s == nil {
		return nil, fmt.Errorf("%w:%s", errBadInput, "found nil on init")
	}
	if len(opt.Cipher) == 0 || len(opt.Auth) == 0 {
		return nil, fmt.Errorf("%w:%s", errBadInput, "empty options")
	}
	state := &dataChannelState{}
	data := &data{options: opt, session: s, state: state}

	logger.Info(fmt.Sprintf("Cipher: %s", opt.Cipher))

	dataCipher, err := newDataCipherFromCipherSuite(opt.Cipher)
	if err != nil {
		return data, err
	}
	data.state.dataCipher = dataCipher
	switch dataCipher.isAEAD() {
	case true:
		data.decodeFn = decodeEncryptedPayloadAEAD
		data.encryptEncodeFn = encryptAndEncodePayloadAEAD
	case false:
		data.decodeFn = decodeEncryptedPayloadNonAEAD
		data.encryptEncodeFn = encryptAndEncodePayloadNonAEAD
	}

	logger.Info(fmt.Sprintf("Auth:   %s", opt.Auth))

	hmac, ok := newHMACFactory(strings.ToLower(opt.Auth))
	if !ok {
		return data, fmt.Errorf("%w:%s", errBadInput, "no such mac")
	}
	data.state.hmac = hmac
	data.state.hmacSize = getHashLength(strings.ToLower(opt.Auth))

	data.decryptFn = state.dataCipher.decrypt

	return data, nil
}

// DecodeEncryptedPayload calls the corresponding function for AEAD or Non-AEAD decryption.
func (d *data) DecodeEncryptedPayload(b []byte, dcs *dataChannelState) (*encryptedData, error) {
	return d.decodeFn(b, dcs)
}

// SetSetupKeys performs the key expansion from the local and remote
// keySources, initializing the data channel state.
func (d *data) SetupKeys(dck *dataChannelKey) error {
	if dck == nil {
		return fmt.Errorf("%w: %s", errBadInput, "nil args")
	}
	if !dck.ready {
		return fmt.Errorf("%w: %s", errDataChannelKey, "key not ready")
	}
	master := prf(
		dck.local.preMaster[:],
		[]byte("OpenVPN master secret"),
		dck.local.r1[:],
		dck.remote.r1[:],
		[]byte{}, []byte{},
		48)

	keys := prf(
		master,
		[]byte("OpenVPN key expansion"),
		dck.local.r2[:],
		dck.remote.r2[:],
		d.session.LocalSessionID[:], d.session.RemoteSessionID[:],
		256)

	var keyLocal, hmacLocal, keyRemote, hmacRemote keySlot
	copy(keyLocal[:], keys[0:64])
	copy(hmacLocal[:], keys[64:128])
	copy(keyRemote[:], keys[128:192])
	copy(hmacRemote[:], keys[192:256])

	d.state.cipherKeyLocal = keyLocal
	d.state.hmacKeyLocal = hmacLocal
	d.state.cipherKeyRemote = keyRemote
	d.state.hmacKeyRemote = hmacRemote

	logger.Debugf("Cipher key local:  %x", keyLocal)
	logger.Debugf("Cipher key remote: %x", keyRemote)
	logger.Debugf("Hmac key local:    %x", hmacLocal)
	logger.Debugf("Hmac key remote:   %x", hmacRemote)

	logger.Info("Key derivation OK")
	return nil
}

//
// write + encrypt
//

// encrypt calls the corresponding function for AEAD or Non-AEAD decryption.
// Due to the particularities of the iv generation on each of the modes, encryption and encoding are
// done together in the same function.
// TODO accept state for symmetry
func (d *data) EncryptAndEncodePayload(plaintext []byte, dcs *dataChannelState) ([]byte, error) {
	blockSize := dcs.dataCipher.blockSize()

	padded, err := maybeAddCompressPadding(plaintext, d.options.Compress, blockSize)
	if err != nil {
		return []byte{}, fmt.Errorf("%w:%s", errCannotEncrypt, err)
	}

	encrypted, err := d.encryptEncodeFn(padded, d.session, d.state)
	if err != nil {
		return []byte{}, fmt.Errorf("%w:%s", errCannotEncrypt, err)
	}
	return encrypted, nil

}

// encryptAndEncodePayloadAEAD peforms encryption and encoding of the payload in AEAD modes (i.e., AES-GCM).
// TODO for testing we can pass both the state object and the encryptFn FIXME refactor...
func encryptAndEncodePayloadAEAD(padded []byte, session *session, state *dataChannelState) ([]byte, error) {
	nextPacketID, err := session.LocalPacketID()
	if err != nil {
		return []byte{}, fmt.Errorf("bad packet id")
	}

	// we will pass packetID as the aead data to be authenticated
	aead := &bytes.Buffer{}
	bufWriteUint32(aead, uint32(nextPacketID))

	// the iv is the packetID (again) concatenated with the 8 bytes of the
	// key derived for local hmac (which we do not use for anything else in AEAD mode).
	iv := &bytes.Buffer{}
	bufWriteUint32(iv, uint32(nextPacketID))
	iv.Write(state.hmacKeyLocal[:8])

	data := &plaintextData{
		iv:        iv.Bytes(),
		plaintext: padded,
		aead:      aead.Bytes(),
	}

	encryptFn := state.dataCipher.encrypt
	encrypted, err := encryptFn(state.cipherKeyLocal[:], data)
	if err != nil {
		return []byte{}, err
	}

	// some reordering, because openvpn uses tag | payload
	boundary := len(encrypted) - 16
	tag := encrypted[boundary:]
	ciphertext := encrypted[:boundary]

	// we now write to the output buffer
	out := bytes.Buffer{}
	out.Write(data.aead) // the packet_id
	out.Write(tag)
	out.Write(ciphertext)
	return out.Bytes(), nil

}

// encryptAndEncodePayloadNonAEAD peforms encryption and encoding of the payload in Non-AEAD modes (i.e., AES-CBC).
func encryptAndEncodePayloadNonAEAD(padded []byte, session *session, state *dataChannelState) ([]byte, error) {
	// For iv generation, OpenVPN uses a nonce-based PRNG that is initially seeded with
	// OpenSSL RAND_bytes function. I am assuming this is good enough for our current purposes.
	blockSize := state.dataCipher.blockSize()

	iv, err := randomFn(int(blockSize))
	if err != nil {
		return []byte{}, err
	}
	data := &plaintextData{
		iv:        iv,
		plaintext: padded,
		aead:      nil,
	}

	encryptFn := state.dataCipher.encrypt
	ciphertext, err := encryptFn(state.cipherKeyLocal[:], data)
	if err != nil {
		return []byte{}, err
	}

	hashSize := state.hmacSize
	key := state.hmacKeyLocal[:hashSize]

	// TODO reuse mac and Reset()
	mac := hmac.New(state.hmac, key)
	mac.Write(iv)
	mac.Write(ciphertext)
	computedMAC := mac.Sum(nil)

	out := &bytes.Buffer{}
	out.Write(computedMAC)
	out.Write(iv)
	out.Write(ciphertext)
	return out.Bytes(), nil
}

// maybeAddCompressStub adds compression bytes if needed by the passed compression options.
// if the compression stub is on, it sends the first byte to the last position,
// and it adds the compression preamble, according to the spec. compression
// lzo-no also adds a preamble. It returns a byte array and an error if the
// operation could not be completed.
func maybeAddCompressStub(b []byte, opt *Options) ([]byte, error) {
	if opt == nil {
		return nil, fmt.Errorf("%w:%s", errBadInput, "passed nil opts")
	}
	switch opt.Compress {
	case "stub":
		// compression stub: swap first and last byte
		b = append(b, b[0])
		b[0] = 0xfb
	case "lzo-no":
		// old "comp-lzo no" option
		b = append([]byte{0xfa}, b...)
	}
	return b, nil
}

// maybeAddCompressPadding does pkcs7 padding of the encryption payloads as
// needed. if we're using the compression stub the padding is applied without taking the
// traling bit into account. it returns the resulting byte array, and an error
// if the operatio could not be completed.
func maybeAddCompressPadding(b []byte, compress compression, blockSize uint8) ([]byte, error) {
	if compress == "stub" {
		// if we're using the compression stub
		// we need to account for the trailing byte
		// that we have appended in a previous step.
		endByte := b[len(b)-1]
		padded, err := bytesPadPKCS7(b[:len(b)-1], int(blockSize))

		if err != nil {
			return nil, err
		}
		padded[len(padded)-1] = endByte
		return padded, nil
	}
	padded, err := bytesPadPKCS7(b, int(blockSize))
	if err != nil {
		return nil, err
	}
	return padded, nil
}

func (d *data) WritePacket(conn net.Conn, payload []byte) (int, error) {
	panicIfTrue(d.state == nil, "data: nil state")
	panicIfTrue(d.state.dataCipher == nil, "data.state: nil dataCipher")

	buf := bytes.Buffer{}
	switch d.state.dataCipher.isAEAD() {
	case true:
		buf.Write(payload)
	case false:
		packetID := make([]byte, 4)
		localPacketID, _ := d.session.LocalPacketID()
		binary.BigEndian.PutUint32(packetID, uint32(localPacketID))
		buf.Write(packetID[:])
		buf.Write(payload)
	}

	// TODO(ainghazal): maybeAddCompressStub should receive a compression type, not options
	plaintext, err := maybeAddCompressStub(buf.Bytes(), d.options)
	if err != nil {
		return 0, fmt.Errorf("%w:%s", errCannotEncrypt, err)
	}
	encrypted, err := d.EncryptAndEncodePayload(plaintext, d.state)

	if err != nil {
		return 0, fmt.Errorf("%w:%s", errCannotEncrypt, err)
	}

	bufOut := bytes.Buffer{}
	// eventually we'll need to write the keyID here too, from session.
	keyID := 0
	header := byte((pDataV1 << 3) | (keyID & 0x07))
	panicIfFalse(header == byte(0x30), "expected header == 0x30")

	bufOut.WriteByte(header)
	bufOut.Write(encrypted)

	out := maybeAddSizeFrame(conn, bufOut.Bytes())

	logger.Debug("data: write packet")
	logger.Debugf(hex.Dump(out))

	return conn.Write(out)
}

//
// read + decrypt
//

func (d *data) decrypt(encrypted []byte) ([]byte, error) {
	if d.decryptFn == nil {
		return []byte{}, errInitError
	}
	if len(d.state.hmacKeyRemote) == 0 {
		logger.Error("decrypt: not ready yet")
		return []byte{}, errCannotDecrypt
	}
	encryptedData, err := d.DecodeEncryptedPayload(encrypted, d.state)

	if err != nil {
		return []byte{}, fmt.Errorf("%w:%s", errCannotDecrypt, err)
	}
	plainText, err := d.decryptFn(d.state.cipherKeyRemote[:], encryptedData)
	if err != nil {
		return []byte{}, fmt.Errorf("%w:%s", errCannotDecrypt, err)
	}
	return plainText, nil
}

func decodeEncryptedPayloadAEAD(buf []byte, state *dataChannelState) (*encryptedData, error) {
	// Sample AES-GCM head: (v1 though, we're doing v1 here. I'm not sure if there're differences)
	//   48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	//   [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	//            [4-byte
	//            IV head]

	// preconditions

	if len(buf) == 0 || len(buf) < 20 {
		return &encryptedData{}, fmt.Errorf("too short: %d bytes", len(buf))
	}
	if len(state.hmacKeyRemote) < 8 {
		return &encryptedData{}, fmt.Errorf("bad remote hmac")
	}
	remoteHMAC := state.hmacKeyRemote[:8]
	packet_id := buf[:4]

	// we need to swap because decryption expects payload|tag
	// but we've got tag | payload instead
	payload := &bytes.Buffer{}
	payload.Write(buf[20:])  // ciphertext
	payload.Write(buf[4:20]) // tag

	// iv := packetID | remoteHMAC
	iv := &bytes.Buffer{}
	iv.Write(packet_id)
	iv.Write(remoteHMAC)

	encrypted := &encryptedData{
		iv:         iv.Bytes(),
		ciphertext: payload.Bytes(),
		aead:       packet_id,
	}
	return encrypted, nil
}

func decodeEncryptedPayloadNonAEAD(buf []byte, state *dataChannelState) (*encryptedData, error) {
	if len(buf) < 28 {
		return &encryptedData{}, fmt.Errorf("%w: too short (%d bytes)", errBadInput, len(buf))
	}
	if state == nil || state.dataCipher == nil {
		return &encryptedData{}, fmt.Errorf("%w: bad state", errBadInput)
	}

	hashSize := state.hmacSize
	key := state.hmacKeyRemote[:hashSize]

	blockSize := state.dataCipher.blockSize()
	recvMAC := buf[:hashSize]
	iv := buf[hashSize : hashSize+blockSize]
	cipherText := buf[hashSize+blockSize:]

	// TODO instead of instantiating it each time, we can call Reset()

	mac := hmac.New(state.hmac, key)
	mac.Write(iv)
	mac.Write(cipherText)
	calcMAC := mac.Sum(nil)

	if !hmac.Equal(calcMAC, recvMAC) {
		logger.Errorf("expected: %x, got: %x", calcMAC, recvMAC)
		return &encryptedData{}, fmt.Errorf("%w:%s", errCannotDecrypt, errBadHMAC)
	}

	encrypted := &encryptedData{
		iv:         iv,
		ciphertext: cipherText,
		aead:       []byte{}, // no AEAD data in this mode, leaving it empty to satisfy common interface
	}
	return encrypted, nil
}

func (d *data) ReadPacket(p *packet) ([]byte, error) {
	if len(p.payload) == 0 {
		return []byte{}, fmt.Errorf("%w:%s", errCannotDecrypt, "empty payload")
	}
	panicIfFalse(p.isData(), "ReadPacket expects data packet")

	plaintext, err := d.decrypt(p.payload)
	if err != nil {
		return []byte{}, err
	}

	// get plaintext payload from the decrypted plaintext
	return maybeDecompress(plaintext, d.state, d.options)
}

// maybeDecompress de-serializes the data from the payload according to the framing
// given by different compression methods. only the different no-compression
// modes are supported at the moment, so no real decompression is done. It
// returns a byte array, and an error if the operation could not be completed
// successfully.
func maybeDecompress(b []byte, st *dataChannelState, opt *Options) ([]byte, error) {
	if st == nil || st.dataCipher == nil {
		return []byte{}, fmt.Errorf("%w:%s", errBadInput, "bad state")
	}
	if opt == nil {
		return []byte{}, fmt.Errorf("%w:%s", errBadInput, "bad options")
	}

	var compr byte // compression type
	var payload []byte

	switch st.dataCipher.isAEAD() {
	case true:
		switch opt.Compress {
		case compressionStub, compressionLZONo:
			compr = b[0]
			payload = b[1:]
		default:
			compr = 0x00
			payload = b[:]
		}
	default:
		remotePacketID := packetID(binary.BigEndian.Uint32(b[:4]))
		lastKnownRemote, err := st.RemotePacketID()
		if err != nil {
			return payload, err
		}
		if remotePacketID <= lastKnownRemote {
			return []byte{}, errReplayAttack
		}
		st.SetRemotePacketID(remotePacketID)
		compr = b[4]
		payload = b[5:]
	}

	switch compr {
	case 0xfb:
		// compression stub swap:
		// we get the last byte and replace the compression byte
		end := payload[len(payload)-1]
		b := payload[:len(payload)-1]
		payload = append([]byte{end}, b...)
	case 0x00, 0xfa:
		// do nothing
		// 0x00 is compress-no,
		// 0xfa is the old no compression or comp-lzo no case.
		// http://build.openvpn.net/doxygen/comp_8h_source.html
		// see: https://community.openvpn.net/openvpn/ticket/952#comment:5
	default:
		errMsg := fmt.Sprintf("cannot handle compression:%x", compr)
		return []byte{}, fmt.Errorf("%w:%s", errBadCompression, errMsg)
	}
	return payload, nil
}

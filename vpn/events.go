package vpn

//
// Catalog of that can be emitted for callers to observe progress of the
// client bootstrap.
//

const (
	EventReady = iota
	EventDialDone
	EventHandshake
	EventReset
	EventTLSConn
	EventTLSHandshake
	EventTLSHandshakeDone
	EventDataInitDone
	EventHandshakeDone
)

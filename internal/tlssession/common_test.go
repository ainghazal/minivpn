package tlssession

import (
	"github.com/ooni/minivpn/internal/model"
	"github.com/ooni/minivpn/internal/runtimex"
	"github.com/ooni/minivpn/internal/session"
	"github.com/ooni/minivpn/pkg/config"
)

func makeTestingSession() *session.Manager {
	cfg, _ := config.NewConfig()
	manager, err := session.NewManager(cfg)
	runtimex.PanicOnError(err, "could not get session manager")
	manager.SetRemoteSessionID(model.SessionID{0x01})
	return manager
}

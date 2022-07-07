package beat

import (
	"github.com/vela-security/vela-beat/account"
	"github.com/vela-security/vela-beat/cpu"
	"github.com/vela-security/vela-beat/disk"
	"github.com/vela-security/vela-beat/group"
	"github.com/vela-security/vela-beat/host"
	"github.com/vela-security/vela-beat/ifconfig"
	"github.com/vela-security/vela-beat/memory"
	"github.com/vela-security/vela-beat/process"
	"github.com/vela-security/vela-beat/service"
	"github.com/vela-security/vela-beat/ss"
	"github.com/vela-security/vela-beat/track"
	"github.com/vela-security/vela-public/assert"
)

func WithEnv(env assert.Environment) {
	otherByEnv(env)
	account.WithEnv(env)
	group.WithEnv(env)
	host.WithEnv(env)
	cpu.WithEnv(env)
	memory.WithEnv(env)
	disk.WithEnv(env)
	process.WithEnv(env)
	ss.WithEnv(env)
	ifconfig.WithEnv(env)
	service.WithEnv(env)
	track.WithEnv(env)
}

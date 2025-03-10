package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/zxhio/xdpass/pkg/xdp"
)

type Config struct {
	PollTimeoutMs int               `toml:"poll_timeout_ms"`
	Cores         []int             `toml:"cores"`
	Interfaces    []InterfaceConfig `toml:"interfaces"`
}

type InterfaceConfig struct {
	Name       string            `toml:"name"`
	QueueID    int               `toml:"queue_id"`
	AttachMode xdp.XDPAttachMode `toml:"attach_mode"`

	// Bind flags
	ForceZeroCopy bool `toml:"force_zero_copy,omitempty"`
	ForceCopy     bool `toml:"force_copy,omitempty"`
	NoNeedWakeup  bool `toml:"no_need_wakeup"`

	// Internal
	XDPOpts []xdp.XDPOpt `toml:"-"`
}

func DefaultConfigOffload() *Config {
	return &Config{
		Cores: []int{0, 2},
		Interfaces: []InterfaceConfig{
			{
				Name:          "br1",
				QueueID:       -1,
				AttachMode:    xdp.XDPAttachModeNative,
				ForceZeroCopy: true,
				NoNeedWakeup:  false,
			},
		},
	}
}

func DefaultConfigGeneric() *Config {
	return &Config{
		PollTimeoutMs: 10,
		Interfaces: []InterfaceConfig{
			{
				Name:         "eth0",
				QueueID:      0,
				AttachMode:   xdp.XDPAttachModeGeneric,
				ForceCopy:    true,
				NoNeedWakeup: false,
			},
		},
	}
}

func NewConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	for _, cfg := range cfg.Interfaces {
		if err := validateInterfaceConfig(&cfg); err != nil {
			return nil, err
		}

		if cfg.ForceZeroCopy {
			cfg.XDPOpts = append(cfg.XDPOpts, xdp.WithZeroCopy())
		} else if cfg.ForceCopy {
			cfg.XDPOpts = append(cfg.XDPOpts, xdp.WithCopy())
		}
		if cfg.NoNeedWakeup {
			cfg.XDPOpts = append(cfg.XDPOpts, xdp.WithNoNeedWakeup())
		}
	}

	return &cfg, nil
}

func validateInterfaceConfig(cfg *InterfaceConfig) error {
	if cfg.Name == "" {
		return fmt.Errorf("interface name is required")
	}

	if cfg.ForceZeroCopy && cfg.ForceCopy {
		return fmt.Errorf("only one bind flags is allowed")
	}
	return nil
}

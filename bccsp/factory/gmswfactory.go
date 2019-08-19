package factory

import (
	"github.com/chinaso/fabricGM/bccsp"
	"github.com/chinaso/fabricGM/bccsp/gmsw"
	"github.com/pkg/errors"
)

const (
	gmSoftwareBasedFactoryName = "GMSW"
)


type GMSWFactory struct{}

func (f *GMSWFactory) Name() string {
	return gmSoftwareBasedFactoryName
}


// Get returns an instance of BCCSP using Opts.
func (f *GMSWFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.SwOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	swOpts := config.SwOpts


	//fmt.Println("ssss")
	var ks bccsp.KeyStore

	if swOpts.Ephemeral == true {
		ks = gmsw.NewDummyKeyStore()
	} else if swOpts.FileKeystore != nil {
		fks, err := gmsw.NewFileBasedGMKeyStore(nil, swOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to initialize software key store")
		}
		ks = fks

	} else if swOpts.InmemKeystore != nil {
		ks = gmsw.NewInMemoryGMKeyStore()

	} else {
		// Default to ephemeral key store
		ks = gmsw.NewDummyKeyStore()
	}

	return gmsw.NewWithParams(swOpts.SecLevel, swOpts.HashFamily, ks)
}

// SwOpts contains options for the SWFactory
type GMSwOpts struct {
	// Default algorithms when not specified (Deprecated?)
	SecLevel   int    `mapstructure:"security" json:"security" yaml:"Security"`
	HashFamily string `mapstructure:"hash" json:"hash" yaml:"Hash"`

	// Keystore Options
	Ephemeral     bool               `mapstructure:"tempkeys,omitempty" json:"tempkeys,omitempty"`
	FileKeystore  *FileKeystoreOpts  `mapstructure:"filekeystore,omitempty" json:"filekeystore,omitempty" yaml:"FileKeyStore"`
	DummyKeystore *DummyKeystoreOpts `mapstructure:"dummykeystore,omitempty" json:"dummykeystore,omitempty"`
	InmemKeystore *InmemKeystoreOpts `mapstructure:"inmemkeystore,omitempty" json:"inmemkeystore,omitempty"`
}


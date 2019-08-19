package factory

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestGMSWFactoryName(t *testing.T) {
	f := &GMSWFactory{}
	assert.Equal(t, f.Name(), gmSoftwareBasedFactoryName)
}

func TestGMSWFactoryGetInvalidArgs(t *testing.T) {
	f := &GMSWFactory{}

	_, err := f.Get(nil)
	assert.Error(t, err, "Invalid config. It must not be nil.")

	_, err = f.Get(&FactoryOpts{})
	assert.Error(t, err, "Invalid config. It must not be nil.")

	opts := &FactoryOpts{
		SwOpts: &SwOpts{},
	}
	_, err = f.Get(opts)
	assert.Error(t, err, "CSP:500 - Failed initializing configuration at [0,]")
}

func TestGMSWFactoryGet(t *testing.T) {
	f := &GMSWFactory{}

	opts := &FactoryOpts{
		SwOpts: &SwOpts{
			SecLevel:   256,
			HashFamily: "SM3",
		},
	}
	csp, err := f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)

	opts = &FactoryOpts{
		SwOpts: &SwOpts{
			SecLevel:     256,
			HashFamily:   "SM3",
			FileKeystore: &FileKeystoreOpts{KeyStorePath: os.TempDir()},
		},
	}
	csp, err = f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)

}


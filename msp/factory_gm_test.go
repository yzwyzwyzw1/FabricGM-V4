package msp

import (
	"github.com/stretchr/testify/assert"
	"reflect"
	"runtime"
	"testing"
)

func TestGMNewInvalidOpts(t *testing.T) {
	i, err := GMNew(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid msp.NewOpts instance. It must be either *BCCSPNGMNewOpts or *IdemixGMNewOpts. It was [<nil>]")
	assert.Nil(t, i)

	i, err = GMNew(&BCCSPNGMNewOpts{NewBaseGMOpts{Version: -1}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid *BCCSPNGMNewOpts. Version not recognized [-1]")
	assert.Nil(t, i)

	i, err = GMNew(&IdemixGMNewOpts{NewBaseGMOpts{Version: -1}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid *IdemixGMNewOpts. Version not recognized [-1]")
	assert.Nil(t, i)
}

func TestGMNew(t *testing.T) {
	i, err := GMNew(&BCCSPNGMNewOpts{NewBaseGMOpts{Version: MSPv1_0}})
	assert.NoError(t, err)
	assert.NotNil(t, i)
	assert.Equal(t, MSPVersion(MSPv1_0), i.(*bccspmsp).version)
	assert.Equal(t,
		runtime.FuncForPC(reflect.ValueOf(i.(*bccspmsp).internalSetupFunc).Pointer()).Name(),
		runtime.FuncForPC(reflect.ValueOf(i.(*bccspmsp).setupV1).Pointer()).Name(),
	)
	assert.Equal(t,
		runtime.FuncForPC(reflect.ValueOf(i.(*bccspmsp).internalValidateIdentityOusFunc).Pointer()).Name(),
		runtime.FuncForPC(reflect.ValueOf(i.(*bccspmsp).validateIdentityOUsV1).Pointer()).Name(),
	)

	i, err = GMNew(&BCCSPNGMNewOpts{NewBaseGMOpts{Version: MSPv1_1}})
	assert.NoError(t, err)
	assert.NotNil(t, i)
	assert.Equal(t, MSPVersion(MSPv1_1), i.(*bccspmsp).version)
	assert.Equal(t,
		runtime.FuncForPC(reflect.ValueOf(i.(*bccspmsp).internalSetupFunc).Pointer()).Name(),
		runtime.FuncForPC(reflect.ValueOf(i.(*bccspmsp).setupV11).Pointer()).Name(),
	)
	assert.Equal(t,
		runtime.FuncForPC(reflect.ValueOf(i.(*bccspmsp).internalValidateIdentityOusFunc).Pointer()).Name(),
		runtime.FuncForPC(reflect.ValueOf(i.(*bccspmsp).validateIdentityOUsV11).Pointer()).Name(),
	)

	i, err = GMNew(&IdemixGMNewOpts{NewBaseGMOpts{Version: MSPv1_0}})
	assert.Error(t, err)
	assert.Nil(t, i)
	assert.Contains(t, err.Error(), "Invalid *IdemixGMNewOpts. Version not recognized [0]")

	i, err = GMNew(&IdemixGMNewOpts{NewBaseGMOpts{Version: MSPv1_1}})
	assert.NoError(t, err)
	assert.NotNil(t, i)
}


package msp

import "github.com/pkg/errors"


// NewBaseOpts is the default base type for all MSP instantiation Opts
type NewBaseGMOpts struct {
	Version MSPVersion
}

func (o *NewBaseGMOpts) GetVersion() MSPVersion {
	return o.Version
}

// BCCSPNewOpts contains the options to instantiate a new BCCSP-based (X509) MSP
type BCCSPNGMNewOpts struct {
	NewBaseGMOpts
}

// IdemixNewOpts contains the options to instantiate a new Idemix-based MSP
type IdemixGMNewOpts struct {
	NewBaseGMOpts
}

// New create a new MSP instance depending on the passed Opts
func GMNew(opts NewOpts) (MSP, error) {
	switch opts.(type) {
	case *BCCSPNewOpts:
		switch opts.GetVersion() {
		case MSPv1_0:
			return newBccspGMMsp(MSPv1_0)
		case MSPv1_1:
			return newBccspGMMsp(MSPv1_1)
		case MSPv1_3:
			return newBccspGMMsp(MSPv1_3)
		default:
			return nil, errors.Errorf("Invalid *BCCSPNewOpts. Version not recognized [%v]", opts.GetVersion())
		}
	case *IdemixNewOpts:
		switch opts.GetVersion() {
		case MSPv1_3:
			return newBccspGMMsp(MSPv1_3)
		case MSPv1_1:
			return newBccspGMMsp(MSPv1_1)
		default:
			return nil, errors.Errorf("Invalid *IdemixNewOpts. Version not recognized [%v]", opts.GetVersion())
		}
	default:
		return nil, errors.Errorf("Invalid msp.NewOpts instance. It must be either *BCCSPNewOpts or *IdemixNewOpts. It was [%v]", opts)
	}
}

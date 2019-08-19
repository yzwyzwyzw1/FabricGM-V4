package tls

import (
	"errors"
	"fmt"
	"github.com/chinaso/fabricGM/cryptopkg/golangGM/x509"
	"net"
	"testing"
	"time"
)

func TestVerifyPeerCertificategm(t *testing.T) {
	issuer, err := x509.ParseCertificate(testSM2Certificate) // !!!
	if err != nil {
		panic(err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(issuer)

	now := func() time.Time { return time.Unix(1476984729, 0) }

	sentinelErr := errors.New("TestVerifyPeerCertificate")

	verifyCallback := func(called *bool, rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
		if l := len(rawCerts); l != 1 {
			return fmt.Errorf("got len(rawCerts) = %d, wanted 1", l)
		}
		if len(validatedChains) == 0 {
			return errors.New("got len(validatedChains) = 0, wanted non-zero")
		}
		*called = true
		return nil
	}

	tests := []struct {
		configureServer func(*Config, *bool)
		configureClient func(*Config, *bool)
		validate        func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error)
	}{
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					return verifyCallback(called, rawCerts, validatedChains)
				}
			},
			configureClient: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					return verifyCallback(called, rawCerts, validatedChains)
				}
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if clientErr != nil {
					t.Errorf("test[%d]: client handshake failed: %v", testNo, clientErr)
				}
				if serverErr != nil {
					t.Errorf("test[%d]: server handshake failed: %v", testNo, serverErr)
				}
				if !clientCalled {
					t.Errorf("test[%d]: client did not call callback", testNo)
				}
				if !serverCalled {
					t.Errorf("test[%d]: server did not call callback", testNo)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					return sentinelErr
				}
			},
			configureClient: func(config *Config, called *bool) {
				config.VerifyPeerCertificate = nil
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if serverErr != sentinelErr {
					t.Errorf("#%d: got server error %v, wanted sentinelErr", testNo, serverErr)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
			},
			configureClient: func(config *Config, called *bool) {
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					return sentinelErr
				}
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if clientErr != sentinelErr {
					t.Errorf("#%d: got client error %v, wanted sentinelErr", testNo, clientErr)
				}
			},
		},
		{
			configureServer: func(config *Config, called *bool) {
				config.InsecureSkipVerify = false
			},
			configureClient: func(config *Config, called *bool) {
				config.InsecureSkipVerify = true
				config.VerifyPeerCertificate = func(rawCerts [][]byte, validatedChains [][]*x509.Certificate) error {
					if l := len(rawCerts); l != 1 {
						return fmt.Errorf("got len(rawCerts) = %d, wanted 1", l)
					}
					// With InsecureSkipVerify set, this
					// callback should still be called but
					// validatedChains must be empty.
					if l := len(validatedChains); l != 0 {
						return fmt.Errorf("got len(validatedChains) = %d, wanted zero", l)
					}
					*called = true
					return nil
				}
			},
			validate: func(t *testing.T, testNo int, clientCalled, serverCalled bool, clientErr, serverErr error) {
				if clientErr != nil {
					t.Errorf("test[%d]: client handshake failed: %v", testNo, clientErr)
				}
				if serverErr != nil {
					t.Errorf("test[%d]: server handshake failed: %v", testNo, serverErr)
				}
				if !clientCalled {
					t.Errorf("test[%d]: client did not call callback", testNo)
				}
			},
		},
	}

	for i, test := range tests {
		c, s := net.Pipe()
		done := make(chan error)

		var clientCalled, serverCalled bool

		go func() {
			config := testConfig.Clone()
			config.ServerName = "example.golang"
			config.ClientAuth = RequireAndVerifyClientCert
			config.ClientCAs = rootCAs
			config.Time = now
			test.configureServer(config, &serverCalled)

			err = Server(s, config).Handshake()
			s.Close()
			done <- err
		}()

		config := testConfig.Clone()
		config.ServerName = "example.golang"
		config.RootCAs = rootCAs
		config.Time = now
		test.configureClient(config, &clientCalled)
		clientErr := Client(c, config).Handshake()
		c.Close()
		serverErr := <-done

		test.validate(t, i, clientCalled, serverCalled, clientErr, serverErr)
	}
}

func TestHandshakeClientECDHESM2SM4(t *testing.T) {
	test := &clientTest{
		name:    "ECDHE-SM2-SM4",
		command: []string{"openssl", "s_server", "-cipher", "ECDHE-SM2-SM4128-SM3"},
		cert:    testSM2Certificate,
		key:     testSM2PrivateKey,
	}
	runClientTestTLS12(t, test)
}
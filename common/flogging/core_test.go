/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package flogging_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/chinaso/fabricGM/common/flogging"
	"github.com/chinaso/fabricGM/common/flogging/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

func TestCoreWith(t *testing.T) {
	core := &flogging.Core{
		Encoders: map[flogging.Encoding]zapcore.Encoder{},
		Observer: &mock.Observer{},
	}
	clone := core.With([]zapcore.Field{zap.String("key", "value")})
	assert.Equal(t, core, clone)

	jsonEncoder := zapcore.NewJSONEncoder(zapcore.EncoderConfig{})
	consoleEncoder := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{})
	core = &flogging.Core{
		Encoders: map[flogging.Encoding]zapcore.Encoder{
			flogging.JSON:    jsonEncoder,
			flogging.CONSOLE: consoleEncoder,
		},
	}
	decorated := core.With([]zapcore.Field{zap.String("key", "value")})

	// verify the objects differ
	assert.NotEqual(t, core, decorated)

	// verify the objects only differ by the encoded fields
	jsonEncoder.AddString("key", "value")
	consoleEncoder.AddString("key", "value")
	assert.Equal(t, core, decorated)
}

func TestCoreCheck(t *testing.T) {
	var enabledArgs []zapcore.Level
	levels := &flogging.LoggerLevels{}
	err := levels.ActivateSpec("warning")
	assert.NoError(t, err)
	core := &flogging.Core{
		LevelEnabler: zap.LevelEnablerFunc(func(l zapcore.Level) bool {
			enabledArgs = append(enabledArgs, l)
			return l >= zapcore.WarnLevel
		}),
		Levels: levels,
	}

	// not enabled
	ce := core.Check(zapcore.Entry{Level: zapcore.DebugLevel}, nil)
	assert.Nil(t, ce)
	ce = core.Check(zapcore.Entry{Level: zapcore.InfoLevel}, nil)
	assert.Nil(t, ce)

	// enabled
	ce = core.Check(zapcore.Entry{Level: zapcore.WarnLevel}, nil)
	assert.NotNil(t, ce)

	assert.Equal(t, enabledArgs, []zapcore.Level{zapcore.DebugLevel, zapcore.InfoLevel, zapcore.WarnLevel})
}

type sw struct {
	bytes.Buffer
	writeErr   error
	syncCalled bool
	syncErr    error
}

func (s *sw) Sync() error {
	s.syncCalled = true
	return s.syncErr
}

func (s *sw) Write(b []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return s.Buffer.Write(b)
}

func (s *sw) Encoding() flogging.Encoding {
	return flogging.CONSOLE
}

func TestCoreWrite(t *testing.T) {
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoderConfig.EncodeTime = nil

	output := &sw{}
	core := &flogging.Core{
		Encoders: map[flogging.Encoding]zapcore.Encoder{
			flogging.CONSOLE: zapcore.NewConsoleEncoder(encoderConfig),
		},
		Selector: output,
		Output:   output,
	}

	entry := zapcore.Entry{
		Level:   zapcore.InfoLevel,
		Message: "this is a message",
	}
	err := core.Write(entry, nil)
	assert.NoError(t, err)
	assert.Equal(t, "INFO\tthis is a message\n", output.String())

	output.writeErr = errors.New("super-loose")
	err = core.Write(entry, nil)
	assert.EqualError(t, err, "super-loose")
}

func TestCoreWriteSync(t *testing.T) {
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	encoderConfig.EncodeTime = nil

	output := &sw{}
	core := &flogging.Core{
		Encoders: map[flogging.Encoding]zapcore.Encoder{
			flogging.CONSOLE: zapcore.NewConsoleEncoder(encoderConfig),
		},
		Selector: output,
		Output:   output,
	}

	entry := zapcore.Entry{
		Level:   zapcore.DebugLevel,
		Message: "no bugs for me",
	}
	err := core.Write(entry, nil)
	assert.NoError(t, err)
	assert.False(t, output.syncCalled)

	entry = zapcore.Entry{
		Level:   zapcore.PanicLevel,
		Message: "gah!",
	}
	err = core.Write(entry, nil)
	assert.NoError(t, err)
	assert.True(t, output.syncCalled)
}

type brokenEncoder struct{ zapcore.Encoder }

func (b *brokenEncoder) EncodeEntry(zapcore.Entry, []zapcore.Field) (*buffer.Buffer, error) {
	return nil, errors.New("broken encoder")
}

func TestCoreWriteEncodeFail(t *testing.T) {
	output := &sw{}
	core := &flogging.Core{
		Encoders: map[flogging.Encoding]zapcore.Encoder{
			flogging.CONSOLE: &brokenEncoder{},
		},
		Selector: output,
		Output:   output,
	}

	entry := zapcore.Entry{
		Level:   zapcore.DebugLevel,
		Message: "no bugs for me",
	}
	err := core.Write(entry, nil)
	assert.EqualError(t, err, "broken encoder")
}

func TestCoreSync(t *testing.T) {
	syncWriter := &sw{}
	core := &flogging.Core{
		Output: syncWriter,
	}

	err := core.Sync()
	assert.NoError(t, err)
	assert.True(t, syncWriter.syncCalled)

	syncWriter.syncErr = errors.New("bummer")
	err = core.Sync()
	assert.EqualError(t, err, "bummer")
}

func TestObserverCheck(t *testing.T) {
	observer := &mock.Observer{}
	entry := zapcore.Entry{
		Level:   zapcore.DebugLevel,
		Message: "message",
	}
	checkedEntry := &zapcore.CheckedEntry{}

	levels := &flogging.LoggerLevels{}
	levels.ActivateSpec("debug")
	core := &flogging.Core{
		LevelEnabler: zap.LevelEnablerFunc(func(l zapcore.Level) bool { return true }),
		Levels:       levels,
		Observer:     observer,
	}

	ce := core.Check(entry, checkedEntry)
	assert.Exactly(t, ce, checkedEntry)

	assert.Equal(t, 1, observer.CheckCallCount())
	observedEntry, observedCE := observer.CheckArgsForCall(0)
	assert.Equal(t, entry, observedEntry)
	assert.Equal(t, ce, observedCE)
}

func TestObserverWriteEntry(t *testing.T) {
	observer := &mock.Observer{}
	entry := zapcore.Entry{
		Level:   zapcore.DebugLevel,
		Message: "message",
	}
	fields := []zapcore.Field{
		{Key: "key1", Type: zapcore.SkipType},
		{Key: "key2", Type: zapcore.SkipType},
	}

	levels := &flogging.LoggerLevels{}
	levels.ActivateSpec("debug")
	selector := &sw{}
	output := &sw{}
	core := &flogging.Core{
		LevelEnabler: zap.LevelEnablerFunc(func(l zapcore.Level) bool { return true }),
		Levels:       levels,
		Selector:     selector,
		Encoders: map[flogging.Encoding]zapcore.Encoder{
			flogging.CONSOLE: zapcore.NewConsoleEncoder(zapcore.EncoderConfig{}),
		},
		Output:   output,
		Observer: observer,
	}

	err := core.Write(entry, fields)
	assert.NoError(t, err)

	assert.Equal(t, 1, observer.WriteEntryCallCount())
	observedEntry, observedFields := observer.WriteEntryArgsForCall(0)
	assert.Equal(t, entry, observedEntry)
	assert.Equal(t, fields, observedFields)
}

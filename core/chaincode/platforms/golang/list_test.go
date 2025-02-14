/*
Copyright 2017 - Greg Haskins <gregory.haskins@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package golang

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_listDeps(t *testing.T) {
	_, err := listDeps(nil, "github.com/chinaso/fabricGM/peer")
	if err != nil {
		t.Errorf("list failed: %s", err)
	}
}

func Test_runProgram(t *testing.T) {
	_, err := runProgram(
		getEnv(),
		10*time.Millisecond,
		"go",
		"build",
		"github.com/chinaso/fabricGM/peer",
	)
	assert.Contains(t, err.Error(), "timed out")

	_, err = runProgram(
		getEnv(),
		1*time.Second,
		"go",
		"cmddoesnotexist",
	)
	assert.Contains(t, err.Error(), "unknown command")
}

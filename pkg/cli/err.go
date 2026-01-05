// Copyright Project Contour Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import "fmt"

// ExitCode is a process exit code suitable for use with os.Exit.
type ExitCode int

const (
	// ExFail is an exit code indicating an unspecified error.
	ExFail ExitCode = 1

	// ExUsage is an exit code indicating invalid invocation syntax.
	ExUsage ExitCode = 65

	// ExNoInput is an exit code indicating missing input data.
	ExNoInput ExitCode = 66

	// ExDataErr means the input data was incorrect in some
	// way. This should only be used for user's data and not
	// system files.
	ExDataErr ExitCode = 65

	// ExConfig means that something was found in an unconfigured
	// or misconfigured state.
	ExConfig ExitCode = 78
)

// ExitError captures an ExitCode and its associated error message.
type ExitError struct {
	Code ExitCode
	Err  error
}

func (e ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}

	return ""
}

// ExitErrorf formats and error message along with the ExitCode.
func ExitErrorf(code ExitCode, format string, args ...interface{}) error {
	return &ExitError{
		Code: code,
		Err:  fmt.Errorf(format, args...),
	}
}

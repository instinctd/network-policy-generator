package k8s

import (
	"fmt"
	"io"
	"strings"
)

// FakeCommander implements Commander for testing.
// Set Responses[name] to the bytes Output should return, or Errors[name] to
// make a command fail.
type FakeCommander struct {
	Responses map[string][]byte
	Errors    map[string]error
}

// NewFakeCommander returns a FakeCommander with empty maps.
func NewFakeCommander() *FakeCommander {
	return &FakeCommander{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
}

func (f *FakeCommander) Output(name string, args ...string) ([]byte, error) {
	key := cmdKey(name, args)
	if err, ok := f.Errors[key]; ok {
		return nil, err
	}
	if err, ok := f.Errors[name]; ok {
		return nil, err
	}
	if resp, ok := f.Responses[key]; ok {
		return resp, nil
	}
	if resp, ok := f.Responses[name]; ok {
		return resp, nil
	}
	return nil, fmt.Errorf("FakeCommander: no response for %q", key)
}

func (f *FakeCommander) StdoutPipe(name string, args ...string) (io.ReadCloser, func() error, error) {
	key := cmdKey(name, args)
	if err, ok := f.Errors[key]; ok {
		return nil, nil, err
	}
	if err, ok := f.Errors[name]; ok {
		return nil, nil, err
	}

	var data []byte
	if resp, ok := f.Responses[key]; ok {
		data = resp
	} else if resp, ok := f.Responses[name]; ok {
		data = resp
	} else {
		data = []byte{}
	}

	rc := io.NopCloser(strings.NewReader(string(data)))
	return rc, func() error { return nil }, nil
}

func cmdKey(name string, args []string) string {
	return name + " " + strings.Join(args, " ")
}

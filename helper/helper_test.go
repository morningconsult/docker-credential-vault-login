package helper

import (
	"testing"

	"github.com/hashicorp/go-hclog"
)

func TestNewHelper(t *testing.T) {
	t.SkipNow()
}

func TestHelperGet_Logger(t *testing.T) {
	t.SkipNow()
}

func TestHelper_parseConfig(t *testing.T) {
	h := NewHelper(&HelperOptions{
		Logger: hclog.NewNullLogger(),
	})

	_, _, err := h.Get
}

func TestHelperGet_Cache(t *testing.T) {
	t.SkipNow()
}

func TestHelperGet_GetCreds(t *testing.T) {
	t.SkipNow()
}

package mtproto

import (
	"fmt"

	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/xtls/xray-core/common/errors"
)

type logger struct {
	prefix string
}

func newLogger() mtglib.Logger {
	return &logger{prefix: "mtproto"}
}

func (l *logger) Named(name string) mtglib.Logger {
	return &logger{prefix: l.prefix + "." + name}
}

func (l *logger) BindInt(string, int) mtglib.Logger     { return l }
func (l *logger) BindStr(string, string) mtglib.Logger  { return l }
func (l *logger) BindJSON(string, string) mtglib.Logger { return l }

func (l *logger) Printf(format string, args ...any) {
	errors.LogInfo(nil, l.prefix, ": ", fmt.Sprintf(format, args...))
}

func (l *logger) Info(msg string) {
	errors.LogInfo(nil, l.prefix, ": ", msg)
}

func (l *logger) InfoError(msg string, err error) {
	errors.LogInfoInner(nil, err, l.prefix, ": ", msg)
}

func (l *logger) Warning(msg string) {
	errors.LogWarning(nil, l.prefix, ": ", msg)
}

func (l *logger) WarningError(msg string, err error) {
	errors.LogWarningInner(nil, err, l.prefix, ": ", msg)
}

func (l *logger) Debug(msg string) {
	errors.LogDebug(nil, l.prefix, ": ", msg)
}

func (l *logger) DebugError(msg string, err error) {
	errors.LogDebugInner(nil, err, l.prefix, ": ", msg)
}

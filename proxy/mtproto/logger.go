package mtproto

import (
	"fmt"

	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/xtls/xray-core/common/errors"
)

// xrayLogger bridges mtglib.Logger to Xray's error logging system.
type xrayLogger struct {
	prefix string
}

func newXrayLogger() mtglib.Logger {
	return &xrayLogger{prefix: "mtproto"}
}

func (l *xrayLogger) Named(name string) mtglib.Logger {
	return &xrayLogger{prefix: l.prefix + "." + name}
}

func (l *xrayLogger) BindInt(name string, value int) mtglib.Logger {
	return l
}

func (l *xrayLogger) BindStr(name, value string) mtglib.Logger {
	return l
}

func (l *xrayLogger) BindJSON(name, value string) mtglib.Logger {
	return l
}

func (l *xrayLogger) Printf(format string, args ...any) {
	errors.LogInfo(nil, l.prefix+": "+fmt.Sprintf(format, args...))
}

func (l *xrayLogger) Info(msg string) {
	errors.LogInfo(nil, l.prefix+": "+msg)
}

func (l *xrayLogger) InfoError(msg string, err error) {
	errors.LogInfoInner(nil, err, l.prefix+": "+msg)
}

func (l *xrayLogger) Warning(msg string) {
	errors.LogWarning(nil, l.prefix+": "+msg)
}

func (l *xrayLogger) WarningError(msg string, err error) {
	errors.LogWarningInner(nil, err, l.prefix+": "+msg)
}

func (l *xrayLogger) Debug(msg string) {
	errors.LogDebug(nil, l.prefix+": "+msg)
}

func (l *xrayLogger) DebugError(msg string, err error) {
	errors.LogDebugInner(nil, err, l.prefix+": "+msg)
}

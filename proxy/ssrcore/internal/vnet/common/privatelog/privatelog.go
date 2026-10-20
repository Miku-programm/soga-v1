// Package privatelog isolates upstream packet dumps from the application's
// logger. Protocol errors are returned through the adapter; upstream payload
// diagnostics are not emitted by default, and the global logrus is untouched.
package privatelog

import (
	"github.com/sirupsen/logrus"
	"io"
)

type Fields = logrus.Fields
type Level = logrus.Level
type Entry = logrus.Entry

var logger = func() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}()

var (
	AllLevels  = logrus.AllLevels
	AddHook    = logger.AddHook
	WithFields = logger.WithFields
	Debug      = logger.Debug
	Debugf     = logger.Debugf
	Info       = logger.Info
	Infof      = logger.Infof
	Warn       = logger.Warn
	Warnf      = logger.Warnf
	Warning    = logger.Warning
	Error      = logger.Error
	Errorf     = logger.Errorf
)

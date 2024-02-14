package slogger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

/*
 * Copyright (c) 2024 Norwegian University of Science and Technology, Norway
 */

const (
	// LevelDebug set this logger to log messages at debug level and above.
	LevelDebug = slog.LevelDebug
	// LevelInfo set this logger to log messages at info level and above.
	LevelInfo = slog.LevelInfo
	// LevelWarn set this logger to log messages at warning level and above.
	LevelWarn = slog.LevelWarn
	// LevelError set this logger to log messages at error level.
	LevelError = slog.LevelError
	badKey     = "!BADKEY"
	callerSkip = 3
	maxSize    = 128
	maxBack    = 3
	maxAge     = 28
)

// Option is the type for allowed options.
type Option func(*SLogger) Option

// SLogger is a custom logger that log to stdout and stderr as default.  If a filename is given via options,
// it will log to the given file in addition to stdout and stderr.  The log file will get rotated depending on
// option values, the max file size in megabytes, number of how many old log files to retain, if the old
// log files should be compressed and how long to retain old files.  Check options for default values.
//
// Only log messages with LevelError will be logged to stderr in addition to other destinations.
type SLogger struct {
	file          *slog.Logger
	stdout        *slog.Logger
	stderr        *slog.Logger
	addSource     bool
	level         slog.Level
	options       *slog.HandlerOptions
	stderrOptions *slog.HandlerOptions
	text          bool
	wc            io.WriteCloser
	utc           bool
	filename      string
	maxSize       int
	maxBack       int
	maxAge        int
	localtime     bool
	compress      bool
}

// New creates a new Logger with the given options, if any.  Check options for the default settings.
func New(opts ...Option) *SLogger {
	sl := &SLogger{
		file:      nil,
		stdout:    nil,
		stderr:    nil,
		addSource: false,
		level:     LevelInfo,
		options:   nil,
		text:      false,
		wc:        nil,
		utc:       true,
		filename:  "",
		maxSize:   maxSize,
		maxBack:   maxBack,
		maxAge:    maxAge,
		localtime: false,
		compress:  false,
	}
	for _, opt := range opts {
		opt(sl)
	}

	sl.options = &slog.HandlerOptions{
		AddSource:   sl.addSource,
		Level:       sl.level,
		ReplaceAttr: replaceAttrs,
	}
	if sl.filename != "" {
		sl.wc = &lumberjack.Logger{
			Filename:   sl.filename,
			MaxSize:    sl.maxSize, // megabytes
			MaxBackups: sl.maxBack,
			MaxAge:     sl.maxAge,
			LocalTime:  sl.localtime,
			Compress:   sl.compress,
		}
		sl.file = slog.New(getHandler(sl.wc, sl.text, sl.options))
	}
	sl.stdout = slog.New(getHandler(os.Stdout, sl.text, sl.options))

	sl.stderrOptions = &slog.HandlerOptions{
		AddSource:   sl.addSource,
		Level:       LevelError,
		ReplaceAttr: replaceAttrs,
	}
	sl.stderr = slog.New(getHandler(os.Stderr, sl.text, sl.stderrOptions))

	return sl
}

func getHandler(w io.WriteCloser, text bool, opts *slog.HandlerOptions) slog.Handler {
	if text {
		return slog.NewTextHandler(w, opts)
	}
	return slog.NewJSONHandler(w, opts)
}

func replaceAttrs(groups []string, a slog.Attr) slog.Attr {
	// Remove the directory from the source's filename.
	if a.Key == slog.SourceKey {
		source := a.Value.Any().(*slog.Source)
		source.File = filepath.Base(source.File)
	}
	return a
}

// LogText turn on or off logging in text format.  The default format is JSON.
func LogText(b bool) Option {
	return func(sl *SLogger) Option {
		tmp := sl.text
		sl.text = b
		return LogText(tmp)
	}
}

// LogLevel set the log-level, level can be set to LevelDebug, LevelInfo, LevelWarn or LevelError.
// The default level is LevelInfo.
func LogLevel(l slog.Level) Option {
	return func(sl *SLogger) Option {
		tmp := sl.level
		sl.level = l
		return LogLevel(tmp)
	}
}

// AddSource turn on or of logging of the source file information. The default is off.
func AddSource(b bool) Option {
	return func(sl *SLogger) Option {
		tmp := sl.addSource
		sl.addSource = b
		return AddSource(tmp)
	}
}

// LogUTC turn on or off logging in UTC time, otherwise time will be in local time.  The default is on.
func LogUTC(b bool) Option {
	return func(sl *SLogger) Option {
		tmp := sl.utc
		sl.utc = b
		return LogUTC(tmp)
	}
}

// Filename set the name of a log file in addition to logging to stdout and stderr.  The default is no file,
// i.e. only logging to stdout and stderr.
func Filename(s string) Option {
	return func(sl *SLogger) Option {
		tmp := sl.filename
		sl.filename = s
		return Filename(tmp)
	}
}

// MaxSize set the max number of megabytes in size before the log file is rotated. The default is 128 megabytes.
func MaxSize(s int) Option {
	return func(sl *SLogger) Option {
		tmp := sl.maxSize
		sl.maxSize = s
		return MaxSize(tmp)
	}
}

// MaxBack set the number of old log files to retain.  The default is 3 files.
func MaxBack(b int) Option {
	return func(sl *SLogger) Option {
		tmp := sl.maxBack
		sl.maxBack = b
		return MaxBack(tmp)
	}
}

// MaxAge set the max number of days the old log files are retained.  The default is 28 days.
func MaxAge(a int) Option {
	return func(sl *SLogger) Option {
		tmp := sl.maxAge
		sl.maxAge = a
		return MaxAge(tmp)
	}
}

// LocalTime set if the old log files should have a postfix in local time.  The default is off
// and the old log file postfix is in UTC time.
func LocalTime(b bool) Option {
	return func(sl *SLogger) Option {
		tmp := sl.localtime
		sl.localtime = b
		return LocalTime(tmp)
	}
}

// Compress set compression of old log files to on or off.  The default is off.
func Compress(b bool) Option {
	return func(sl *SLogger) Option {
		tmp := sl.compress
		sl.compress = b
		return Compress(tmp)
	}
}

// Options may set new options for add source, log level and/or UTC in one go for file and stdout,
// but log level for stderr will remain at error level.
func (sl *SLogger) Options(opts ...Option) []Option {
	options := make([]Option, 0, len(opts))
	for _, opt := range opts {
		options = append(options, opt(sl))
	}
	sl.options.Level = sl.level
	sl.options.AddSource = sl.addSource
	sl.stderrOptions.AddSource = sl.addSource
	return options
}

func (sl *SLogger) clone() *SLogger {
	c := *sl
	return &c
}

func (sl *SLogger) handle(ctx context.Context, level slog.Level, r slog.Record) error {
	if sl.file != nil && sl.file.Handler().Enabled(ctx, level) {
		if err := sl.file.Handler().Handle(ctx, r); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to write to %s; error = %v", sl.filename, err)
			return err
		}
	}
	if sl.stdout.Handler().Enabled(ctx, level) {
		if err := sl.stdout.Handler().Handle(ctx, r); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to write to stdput; error = %v", err)
			return err
		}
	}
	if sl.stderr.Handler().Enabled(ctx, level) {
		if err := sl.stderr.Handler().Handle(ctx, r); err != nil {
			_, _ = fmt.Fprintf(os.Stdout, "failed to write to stderr; error = %v", err)
			return err
		}
	}
	return nil
}

func (sl *SLogger) getTime() time.Time {
	if sl.utc {
		return time.Now().UTC()
	}
	return time.Now()
}

func (sl *SLogger) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	// NB! This code cannot be refactored, if refactored the call stack will get out of sync!
	var pcs [1]uintptr
	// skip [runtime.Callers, this function, this function's caller]
	runtime.Callers(callerSkip, pcs[:])
	pc := pcs[0]

	r := slog.NewRecord(sl.getTime(), level, msg, pc)
	r.Add(args...)
	_ = sl.handle(ctx, level, r)
}

func (sl *SLogger) logAttrs(ctx context.Context, level slog.Level, msg string, args ...slog.Attr) {
	// NB! This code cannot be refactored, if refactored the call stack will get out of sync!
	var pcs [1]uintptr
	// skip [runtime.Callers, this function, this function's caller]
	runtime.Callers(callerSkip, pcs[:])
	pc := pcs[0]

	r := slog.NewRecord(sl.getTime(), level, msg, pc)
	r.AddAttrs(args...)
	_ = sl.handle(ctx, level, r)
}

// Debug logs at LevelDebug
func (sl *SLogger) Debug(msg string, args ...any) {
	sl.log(context.Background(), slog.LevelDebug, msg, args...)
}

// DebugContext logs at LevelDebug with the given context.
func (sl *SLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	sl.log(ctx, slog.LevelDebug, msg, args...)
}

// FileEnabled reports whether sl's file logger emits log records at the given context and level.
func (sl *SLogger) FileEnabled(ctx context.Context, l slog.Level) bool {
	if sl.file != nil {
		return sl.file.Enabled(ctx, l)
	}
	return false
}

// StdoutEnabled reports whether sl's stdout logger emits log records at the given context and level.
func (sl *SLogger) StdoutEnabled(ctx context.Context, l slog.Level) bool {
	if sl.stdout != nil {
		return sl.stdout.Enabled(ctx, l)
	}
	return false
}

// Error logs at LevelError.
func (sl *SLogger) Error(msg string, args ...any) {
	sl.log(context.Background(), slog.LevelError, msg, args...)
}

// ErrorContext logs at LevelError with the given context.
func (sl *SLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	sl.log(ctx, slog.LevelError, msg, args...)
}

// FileHandler returns sl's file Handler if logging to file was enabled by options, otherwise nil.
func (sl *SLogger) FileHandler() slog.Handler {
	if sl.file != nil {
		return sl.file.Handler()
	}
	return nil
}

// StdoutHandler returns sl's stdout Handler if stdout has a handler, otherwise nil.
func (sl *SLogger) StdoutHandler() slog.Handler {
	if sl.stdout != nil {
		return sl.stdout.Handler()
	}
	return nil
}

// Info logs at LevelInfo.
func (sl *SLogger) Info(msg string, args ...any) {
	sl.log(context.Background(), slog.LevelInfo, msg, args...)
}

// InfoContext logs at LevelInfo with the given context.
func (sl *SLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	sl.log(ctx, slog.LevelInfo, msg, args...)
}

// Log emits a log record with the current time and the given level and message.
// The Record's Attrs consist of the Logger's attributes followed by
// the Attrs specified by args.
//
// The attribute arguments are processed as follows:
//   - If an argument is an Attr, it is used as is.
//   - If an argument is a string and this is not the last argument,
//     the following argument is treated as the value and the two are combined
//     into an Attr.
//   - Otherwise, the argument is treated as a value with key "!BADKEY".
func (sl *SLogger) Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	sl.log(ctx, level, msg, args...)
}

// LogAttrs is a more efficient version of SLogger.Log that accepts only Attrs.
func (sl *SLogger) LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	sl.logAttrs(ctx, level, msg, attrs...)
}

// Sync flush and close the underlying log file.
func (sl *SLogger) Sync() error {
	if sl.wc != nil {
		return sl.wc.Close()
	}
	return nil
}

// Warn logs at LevelWarn.
func (sl *SLogger) Warn(msg string, args ...any) {
	sl.log(context.Background(), slog.LevelWarn, msg, args...)
}

// WarnContext logs at LevelWarn with the given context.
func (sl *SLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	sl.log(ctx, slog.LevelWarn, msg, args...)
}

// With returns a Logger that includes the given attributes in each output operation. Arguments are
// converted to attributes as if by SLogger.Log.
func (sl *SLogger) With(args ...any) *SLogger {
	if len(args) == 0 {
		return sl
	}
	c := sl.clone()
	if sl.file != nil {
		c.file = slog.New(sl.file.Handler().WithAttrs(argsToAttrSlice(args)))
	}
	c.stdout = slog.New(sl.stdout.Handler().WithAttrs(argsToAttrSlice(args)))
	c.stderr = slog.New(sl.stderr.Handler().WithAttrs(argsToAttrSlice(args)))
	return c
}

// WithGroup returns a Logger that starts a group, if name is non-empty.
// The keys of all attributes added to the Logger will be qualified by the given
// name. (How that qualification happens depends on the [Handler.WithGroup]
// method of the Logger's Handler.)
//
// If name is empty, WithGroup returns the receiver.
func (sl *SLogger) WithGroup(name string) *SLogger {
	if name == "" {
		return sl
	}
	c := sl.clone()
	if sl.file != nil {
		c.file = slog.New(sl.file.Handler().WithGroup(name))
	}
	c.stdout = slog.New(sl.stdout.Handler().WithGroup(name))
	c.stderr = slog.New(sl.stderr.Handler().WithGroup(name))
	return c
}

func argsToAttrSlice(args []any) []slog.Attr {
	var (
		attr  slog.Attr
		attrs []slog.Attr
	)
	for len(args) > 0 {
		attr, args = argsToAttr(args)
		attrs = append(attrs, attr)
	}
	return attrs
}

func argsToAttr(args []any) (slog.Attr, []any) {
	switch x := args[0].(type) {
	case string:
		if len(args) == 1 {
			return slog.String(badKey, x), nil
		}
		return slog.Any(x, args[1]), args[2:]

	case slog.Attr:
		return x, args[1:]

	default:
		return slog.Any(badKey, x), args[1:]
	}
}

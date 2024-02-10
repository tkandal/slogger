package slogger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
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
// it will log to the given file in addition to stdout and stderr. Only log messages with LevelError will
// be logged to stderr.
type SLogger struct {
	file      *slog.Logger
	stdout    *slog.Logger
	stderr    *slog.Logger
	addSource bool
	level     slog.Level
	options   *slog.HandlerOptions
	text      bool
	wc        io.WriteCloser
	utc       bool
	filename  string
	maxSize   int
	maxBack   int
	maxAge    int
	localtime bool
	compress  bool
}

// New will allocate a new SLogger-object and return a pointer to the new SLogger-object.
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

	stderrOptions := &slog.HandlerOptions{
		AddSource:   sl.addSource,
		Level:       LevelError,
		ReplaceAttr: replaceAttrs,
	}
	sl.stderr = slog.New(getHandler(os.Stderr, sl.text, stderrOptions))

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

// AddSource turn on or of logging af the source file. The default is false.
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

// Filename set the name of a log file in addition to logging to stdout and stderr.  The default is empty.
func Filename(s string) Option {
	return func(sl *SLogger) Option {
		tmp := sl.filename
		sl.filename = s
		return Filename(tmp)
	}
}

// MaxSize set the max number for megabytes in size before the log file is rotated. The default is 128 megabytes.
func MaxSize(s int) Option {
	return func(sl *SLogger) Option {
		tmp := sl.maxSize
		sl.maxBack = s
		return MaxSize(tmp)
	}
}

// MaxBack set the number of backup files for the log file.  The default is 3 backup files.
func MaxBack(b int) Option {
	return func(sl *SLogger) Option {
		tmp := sl.maxBack
		sl.maxBack = b
		return MaxBack(tmp)
	}
}

// MaxAge set the max number of days the backup files are retained.  The default is 28 days.
func MaxAge(a int) Option {
	return func(sl *SLogger) Option {
		tmp := sl.maxAge
		sl.maxAge = a
		return MaxAge(tmp)
	}
}

// LocalTime set if the backup files should have a postfix in local time.  The default is off and the file postfix is UTC.
func LocalTime(b bool) Option {
	return func(sl *SLogger) Option {
		tmp := sl.localtime
		sl.localtime = b
		return LocalTime(tmp)
	}
}

// Compress set if the backup files should be compresses with gzip.  The default is off.
func Compress(b bool) Option {
	return func(sl *SLogger) Option {
		tmp := sl.localtime
		sl.compress = b
		return Compress(tmp)
	}
}

func (sl *SLogger) clone() *SLogger {
	c := *sl
	return &c
}

func (sl *SLogger) handle(ctx context.Context, level slog.Level, r slog.Record) {
	if level >= sl.level {
		if sl.file != nil {
			_ = sl.file.Handler().Handle(ctx, r)
		}
		_ = sl.stdout.Handler().Handle(ctx, r)
	}
	if sl.stderr.Handler().Enabled(context.Background(), level) {
		_ = sl.stderr.Handler().Handle(ctx, r)
	}
}

func getCaller() uintptr {
	var pcs [1]uintptr
	// skip [runtime.Callers, this function, this function's caller]
	runtime.Callers(callerSkip, pcs[:])
	return pcs[0]
}

func (sl *SLogger) getTime() time.Time {
	if !sl.utc {
		return time.Now()
	}
	return time.Now().UTC()
}

func (sl *SLogger) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	r := slog.NewRecord(sl.getTime(), level, msg, getCaller())
	r.Add(args...)
	sl.handle(ctx, level, r)
}

func (sl *SLogger) logAttrs(ctx context.Context, level slog.Level, msg string, args ...slog.Attr) {
	r := slog.NewRecord(sl.getTime(), level, msg, getCaller())
	r.AddAttrs(args...)
	sl.handle(ctx, level, r)
}

func (sl *SLogger) Debug(msg string, args ...any) {
	sl.log(context.Background(), slog.LevelDebug, msg, args...)
}

func (sl *SLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	sl.log(ctx, slog.LevelDebug, msg, args...)
}

func (sl *SLogger) Enabled(l slog.Level) bool {
	return sl.level >= l
}

func (sl *SLogger) Error(msg string, args ...any) {
	sl.log(context.Background(), slog.LevelError, msg, args...)
}

func (sl *SLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	sl.log(ctx, slog.LevelError, msg, args...)
}

func (sl *SLogger) Handler() slog.Handler {
	if sl.file != nil {
		return sl.file.Handler()
	}
	return sl.stdout.Handler()
}

func (sl *SLogger) Info(msg string, args ...any) {
	sl.log(context.Background(), slog.LevelInfo, msg, args...)
}

func (sl *SLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	sl.log(ctx, slog.LevelInfo, msg, args...)
}

func (sl *SLogger) Log(ctx context.Context, level slog.Level, msg string, args ...any) {
	sl.log(ctx, level, msg, args...)
}

func (sl *SLogger) LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	sl.logAttrs(ctx, level, msg, attrs...)
}

func (sl *SLogger) Sync() error {
	if sl.wc != nil {
		return sl.wc.Close()
	}
	return nil
}

func (sl *SLogger) Warn(msg string, args ...any) {
	sl.log(context.Background(), slog.LevelWarn, msg, args...)
}

func (sl *SLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	sl.log(ctx, slog.LevelWarn, msg, args...)
}

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

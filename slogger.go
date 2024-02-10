package slogger

import (
	"context"
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

type Option func(*SLogger) Option

type SLogger struct {
	file      *slog.Logger
	stdout    *slog.Logger
	stderr    *slog.Logger
	level     slog.Level
	addSource bool
	options   *slog.HandlerOptions
	filename  string
	maxSize   int
	maxBack   int
	maxAge    int
	localtime bool
	compress  bool
}

func New(opts ...Option) (*SLogger, error) {
	log := &SLogger{
		level:     slog.LevelInfo,
		addSource: false,
		filename:  "",
		maxSize:   maxSize,
		maxBack:   maxBack,
		maxAge:    maxAge,
		localtime: false,
		compress:  false,
	}
	for _, opt := range opts {
		opt(log)
	}
	log.options = &slog.HandlerOptions{
		AddSource:   log.addSource,
		Level:       log.level,
		ReplaceAttr: replaceAttrs,
	}
	if log.filename != "" {
		w := &lumberjack.Logger{
			Filename:   log.filename,
			MaxSize:    log.maxSize, // megabytes
			MaxBackups: log.maxBack,
			MaxAge:     log.maxAge,
			LocalTime:  log.localtime,
			Compress:   log.compress,
		}
		log.file = slog.New(slog.NewJSONHandler(w, log.options))
	}
	log.stdout = slog.New(slog.NewJSONHandler(os.Stdout, log.options))
	// Log errors to stderr too.
	log.stderr = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource:   log.addSource,
		Level:       slog.LevelError,
		ReplaceAttr: replaceAttrs,
	}))
	return log, nil
}

func replaceAttrs(groups []string, a slog.Attr) slog.Attr {
	// Remove the directory from the source's filename.
	if a.Key == slog.SourceKey {
		source := a.Value.Any().(*slog.Source)
		source.File = filepath.Base(source.File)
	}
	return a
}

// Level set the log-level.
func Level(l slog.Level) Option {
	return func(logger *SLogger) Option {
		tmp := logger.level
		logger.level = l
		return Level(tmp)
	}
}

// AddSource turn on or of logging af the source file.
func AddSource(b bool) Option {
	return func(logger *SLogger) Option {
		tmp := logger.addSource
		logger.addSource = b
		return AddSource(tmp)
	}
}

// Filename set the name of a log file in addition to logging to stdout and stderr.
func Filename(s string) Option {
	return func(logger *SLogger) Option {
		tmp := logger.filename
		logger.filename = s
		return Filename(tmp)
	}
}

// MaxSize set the max number for megabytes in size before the log file is rotated.
func MaxSize(s int) Option {
	return func(logger *SLogger) Option {
		tmp := logger.maxSize
		logger.maxBack = s
		return MaxSize(tmp)
	}
}

// MaxBack set the number of backups for the log file.
func MaxBack(b int) Option {
	return func(logger *SLogger) Option {
		tmp := logger.maxBack
		logger.maxBack = b
		return MaxBack(tmp)
	}
}

// MaxAge set the max number of days before the log file is rotated.
func MaxAge(a int) Option {
	return func(logger *SLogger) Option {
		tmp := logger.maxAge
		logger.maxAge = a
		return MaxAge(tmp)
	}
}

// LocalTime set if the backup files should have a postfix in local time.
func LocalTime(b bool) Option {
	return func(logger *SLogger) Option {
		tmp := logger.localtime
		logger.localtime = b
		return LocalTime(tmp)
	}
}

// Compress set if the backup files should be compresses with gzip.
func Compress(b bool) Option {
	return func(logger *SLogger) Option {
		tmp := logger.localtime
		logger.compress = b
		return Compress(tmp)
	}
}

func (sl *SLogger) Options(opts ...Option) []Option {
	options := make([]Option, 0)
	for _, opt := range opts {
		options = append(options, opt(sl))
	}
	sl.options.AddSource = sl.addSource
	sl.options.Level = sl.level
	return options
}

func (sl *SLogger) clone() *SLogger {
	c := *sl
	return &c
}

func (sl *SLogger) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	var pcs [1]uintptr
	// skip [runtime.Callers, this function, this function's caller]
	runtime.Callers(callerSkip, pcs[:])
	pc := pcs[0]
	t := time.Now().UTC()

	r := slog.NewRecord(t, level, msg, pc)
	r.Add(args...)

	if sl.level >= level {
		if sl.file != nil {
			_ = sl.file.Handler().Handle(ctx, r)
		}
		_ = sl.stdout.Handler().Handle(ctx, r)
	}
	if sl.stderr.Handler().Enabled(context.Background(), level) {
		_ = sl.stderr.Handler().Handle(ctx, r)
	}
}

func (sl *SLogger) logAttrs(ctx context.Context, level slog.Level, msg string, args ...slog.Attr) {
	var pcs [1]uintptr
	// skip [runtime.Callers, this function, this function's caller]
	runtime.Callers(callerSkip, pcs[:])
	pc := pcs[0]
	t := time.Now().UTC()

	r := slog.NewRecord(t, level, msg, pc)
	r.AddAttrs(args...)

	if sl.level >= level {
		if sl.file != nil {
			_ = sl.file.Handler().Handle(ctx, r)
		}
		_ = sl.stdout.Handler().Handle(ctx, r)
	}
	if sl.stderr.Handler().Enabled(context.Background(), level) {
		_ = sl.stderr.Handler().Handle(ctx, r)
	}
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

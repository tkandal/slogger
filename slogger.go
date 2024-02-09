package slogger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	badKey     = "!BADKEY"
	callerSkip = 3
)

type Option func(*SLogger) Option

type SLogger struct {
	file      *slog.Logger
	stdout    *slog.Logger
	stderr    *slog.Logger
	level     slog.Level
	addSource bool
	options   *slog.HandlerOptions
}

func New(f io.Writer, opts ...Option) *SLogger {
	if f == nil {
		f = io.Discard
	}
	log := &SLogger{
		level:     slog.LevelInfo,
		addSource: false,
	}
	for _, opt := range opts {
		opt(log)
	}
	log.options = &slog.HandlerOptions{
		AddSource:   log.addSource,
		Level:       log.level,
		ReplaceAttr: replaceAttrs,
	}
	log.file = slog.New(slog.NewJSONHandler(f, log.options))
	log.stdout = slog.New(slog.NewJSONHandler(os.Stdout, log.options))
	// Log errors to stderr too.
	log.stderr = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource:   log.addSource,
		Level:       slog.LevelError,
		ReplaceAttr: replaceAttrs,
	}))
	return log
}

func replaceAttrs(groups []string, a slog.Attr) slog.Attr {
	// Remove the directory from the source's filename.
	if a.Key == slog.SourceKey {
		source := a.Value.Any().(*slog.Source)
		source.File = filepath.Base(source.File)
	}
	return a
}

func Level(l slog.Level) Option {
	return func(logger *SLogger) Option {
		tmp := logger.level
		logger.level = l
		return Level(tmp)
	}
}

func AddSource(b bool) Option {
	return func(logger *SLogger) Option {
		tmp := logger.addSource
		logger.addSource = b
		return AddSource(tmp)
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

	if sl.file.Enabled(ctx, level) {
		_ = sl.file.Handler().Handle(ctx, r)
	}
	if sl.stdout.Enabled(ctx, level) {
		_ = sl.stdout.Handler().Handle(ctx, r)
	}
	if sl.stderr.Enabled(ctx, level) {
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

	if sl.file.Enabled(ctx, level) {
		_ = sl.file.Handler().Handle(ctx, r)
	}
	if sl.stdout.Enabled(ctx, level) {
		_ = sl.stdout.Handler().Handle(ctx, r)
	}
	if sl.stderr.Enabled(ctx, level) {
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
	return sl.file.Enabled(context.Background(), l)
}

func (sl *SLogger) Error(msg string, args ...any) {
	sl.log(context.Background(), slog.LevelError, msg, args...)
}

func (sl *SLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	sl.log(ctx, slog.LevelError, msg, args...)
}

func (sl *SLogger) Handler() slog.Handler {
	return sl.file.Handler()
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
	c.file = slog.New(sl.file.Handler().WithAttrs(argsToAttrSlice(args)))
	c.stdout = slog.New(sl.stdout.Handler().WithAttrs(argsToAttrSlice(args)))
	c.stderr = slog.New(sl.stderr.Handler().WithAttrs(argsToAttrSlice(args)))
	return c
}

func (sl *SLogger) WithGroup(name string) *SLogger {
	if name == "" {
		return sl
	}
	c := sl.clone()
	c.file = slog.New(sl.file.Handler().WithGroup(name))
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

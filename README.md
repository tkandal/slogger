# slogger

SLogger is a structured logger with the ability to log til several destinations.  The
structured  logger in the standard library is only able to log to one destination, but
I wanted to have a logger that could log to several destinations to ease both development
and production.  SLogger is really a wrapper around the standard structured logger slog.

SLogger default logs at info-level to stdout and error-level to stderr.  By using an option
it is also possible to log to a file.  The SLogger will then log to all three destinations,
but only error-level messages will also be logged to stderr at all times.

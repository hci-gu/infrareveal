package observer

import "myapp/debugtrace"

func usableTraceSink(sink debugtrace.Sink) debugtrace.Sink {
	if sink == nil {
		return debugtrace.NopSink{}
	}
	return sink
}

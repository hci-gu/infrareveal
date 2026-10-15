//go:build !linux

package observer

import (
	"context"
	"time"
)

func runPacketCapture(
	ctx context.Context,
	interfaceName string,
	scope ObservationScope,
	onReady func(),
	emit func(PacketActivityEvent),
) error {
	return errPacketCaptureUnsupported
}

func runPacketCaptureHealth(ctx context.Context, iface string, scope ObservationScope, ready func(), emit func(PacketActivityEvent), heartbeat func(time.Time, int64)) error {
	return errPacketCaptureUnsupported
}

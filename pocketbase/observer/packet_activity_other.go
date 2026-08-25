//go:build !linux

package observer

import "context"

func runPacketCapture(
	ctx context.Context,
	interfaceName string,
	scope ObservationScope,
	onReady func(),
	emit func(PacketActivityEvent),
) error {
	return errPacketCaptureUnsupported
}

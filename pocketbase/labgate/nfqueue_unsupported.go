//go:build !linux

package labgate

func NewNFQueue(NFQueueConfig) (PacketQueue, error) { return nil, ErrUnsupported }

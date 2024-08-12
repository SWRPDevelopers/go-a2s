package a2s

import (
	"errors"
)

const (
	A2S_PLAYER_CHALLENGE_REPLY_HEADER = 0x41
)

var (
	ErrBadChallengeResponse = errors.New("Bad challenge response")
)

func (c *Client) getChallenge(header []byte, fullResult byte) ([]byte, bool, error) {
	if err := c.send(header); err != nil {
		return nil, false, fmt.Errorf("failed to send request: %w", err)
	}

	data, err := c.receive()
	if err != nil {
		return nil, false, fmt.Errorf("failed to receive data: %w", err)
	}

	// Handle the case where the server might not send any data
	if len(data) == 0 {
		return nil, false, fmt.Errorf("no data received from server, possibly offline or unresponsive")
	}

	// Ensure the packet is large enough to contain the required uint32
	if len(data) < 4 {
		return nil, false, fmt.Errorf("received data is too short: length %d, expected at least 4 bytes", len(data))
	}

	reader := NewPacketReader(data)

	packetType, ok := reader.TryReadInt32()
	if !ok {
		return nil, false, fmt.Errorf("failed to read packet type: %v", data)
	}

	switch packetType {
	case -2:
		// Handle multi-packet response
		fullData, err := c.collectMultiplePacketResponse(data)
		if err != nil {
			return nil, false, fmt.Errorf("failed to collect multi-packet response: %w", err)
		}
		return fullData, true, nil
	case -1:
		// Single packet, continue processing
	default:
		return nil, false, fmt.Errorf("unexpected packet header: %v", packetType)
	}

	// Check if there is at least one more byte for the header
	if reader.Remaining() < 1 {
		return nil, false, fmt.Errorf("insufficient data to read challenge header: %v", data)
	}

	headerByte := reader.ReadUint8()

	if headerByte == A2S_PLAYER_CHALLENGE_REPLY_HEADER {
		// Check if there are at least 4 more bytes for the challenge number
		if reader.Remaining() < 4 {
			return nil, false, fmt.Errorf("insufficient data for challenge number: %v", data)
		}
		return data[reader.Pos() : reader.Pos()+4], false, nil
	} else if headerByte == fullResult {
		// We have received the full result
		return data, true, nil
	}

	return nil, false, ErrBadChallengeResponse
}

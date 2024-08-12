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

	if len(data) < 4 {
		// Log the error and return it without causing a panic
		return nil, false, fmt.Errorf("received data is too short: %v", data)
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
		// Continue with single packet
	default:
		return nil, false, fmt.Errorf("unexpected packet header: %v", packetType)
	}

	headerByte, ok := reader.TryReadUint8()
	if !ok {
		return nil, false, fmt.Errorf("failed to read challenge header: %v", data)
	}

	if headerByte == A2S_PLAYER_CHALLENGE_REPLY_HEADER {
		// Check if we can read 4 more bytes for the challenge
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

package io

import (
	"encoding/binary"
	"errors"
)

func uint16ToBs(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

type tokenPacket []byte

const udp_max_payload = 65507
const prefix_len = 4

var ErrPacketTooShort = errors.New("packet is too short to contain token")

// Encodes a token that will be accompanied by totalNum many other tokens as a
// packet. Call [Prep] before sending the packet.
func PacketForToken(rawToken []byte, totalNum uint16) tokenPacket {
	if len(rawToken) > udp_max_payload-prefix_len {
		panic("token too big to send in one packet")
	}
	totalBuf := uint16ToBs(totalNum)
	return append([]byte{0, 0, totalBuf[0], totalBuf[1]}, rawToken...)
}

// Assembles the token as byte slice for sending by setting the sets of tokens
// sequence number.
func (packet tokenPacket) Prep(seq uint16) []byte {
	seqBuf := uint16ToBs(seq)
	packet[0] = seqBuf[0]
	packet[1] = seqBuf[1]
	return packet
}

// Parses a packet that was assembled by [PacketForToken] and [Prep]. Returns
// the sequence number, number of tokens to be expected in total, and the token.
func FromPacket(packet []byte) (uint16, int, []byte, error) {
	if len(packet) < prefix_len {
		return 0, 0, nil, ErrPacketTooShort
	} else {
		seq := binary.LittleEndian.Uint16(packet[:2])
		total := int(binary.LittleEndian.Uint16(packet[2:4]))
		return seq, total, packet[4:], nil
	}
}

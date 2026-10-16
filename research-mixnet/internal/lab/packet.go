// SPDX-License-Identifier: AGPL-3.0-or-later
package lab

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const (
	payloadBytes = 4096
	coverKind    = byte(0)
	requestKind  = byte(1)
	responseKind = byte(2)
)

type nodeID = [constants.NodeIDLength]byte
type replyID = [constants.SURBIDLength]byte

// The lab uses the upstream Sphinx construction, not a custom onion cipher.
// X25519 is deliberately a classical test suite, not a post-quantum claim.
type codec struct {
	s      *sphinx.Sphinx
	scheme nike.Scheme
}

func newCodec() *codec {
	scheme := x25519.Scheme(rand.Reader)
	g := geo.GeometryFromUserForwardPayloadLength(scheme, payloadBytes, false, 4)
	return &codec{s: sphinx.NewNIKESphinx(scheme, g), scheme: scheme}
}

func encodeFrame(kind byte, data []byte) ([]byte, error) {
	if kind > responseKind || len(data) > payloadBytes-6 {
		return nil, errors.New("invalid cell payload")
	}
	b := make([]byte, payloadBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0], b[1] = 1, kind
	binary.BigEndian.PutUint32(b[2:6], uint32(len(data)))
	copy(b[6:], data)
	return b, nil
}

func decodeFrame(b []byte) (byte, []byte, error) {
	if len(b) != payloadBytes || b[0] != 1 || b[1] > responseKind {
		return 0, nil, errors.New("invalid cell payload")
	}
	n := int(binary.BigEndian.Uint32(b[2:6]))
	if n > len(b)-6 || (b[1] == coverKind && n != 0) {
		return 0, nil, errors.New("invalid cell payload")
	}
	return b[1], b[6 : 6+n], nil
}

func randomIndex(n int) (int, error) {
	if n < 1 {
		return 0, errors.New("empty selection")
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

func makePath(nodes []*node, reply *replyID) []*sphinx.PathHop {
	path := make([]*sphinx.PathHop, len(nodes))
	for i, n := range nodes {
		path[i] = &sphinx.PathHop{ID: n.id, NIKEPublicKey: n.public}
		if i != len(nodes)-1 {
			path[i].Commands = []commands.RoutingCommand{&commands.NodeDelay{Delay: 0}}
		} else {
			path[i].Commands = []commands.RoutingCommand{&commands.Recipient{}}
			if reply != nil {
				path[i].Commands = append(path[i].Commands, &commands.SURBReply{ID: *reply})
			}
		}
	}
	return path
}

func (c *codec) packet(nodes []*node, kind byte, data []byte) ([]byte, error) {
	frame, err := encodeFrame(kind, data)
	if err != nil {
		return nil, err
	}
	return c.s.NewPacket(rand.Reader, makePath(nodes, nil), frame)
}

func (c *codec) cover(nodes []*node) func() ([]byte, error) {
	return func() ([]byte, error) { return c.packet(nodes, coverKind, nil) }
}

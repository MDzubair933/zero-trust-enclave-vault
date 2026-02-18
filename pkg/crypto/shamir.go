package crypto

import (
	"crypto/rand"
	"errors"
)

type ShamirQuorum struct {
	Threshold int
	Shares    int
}

func NewShamirQuorum(threshold, shares int) (*ShamirQuorum, error) {
	if threshold > shares || threshold < 2 {
		return nil, errors.New("invalid threshold parameters")
	}
	return &ShamirQuorum{Threshold: threshold, Shares: shares}, nil
}

func (s *ShamirQuorum) SplitSecret(secret []byte) ([][]byte, error) {
	shares := make([][]byte, s.Shares)
	for i := 0; i < s.Shares; i++ {
		shares[i] = make([]byte, len(secret))
		rand.Read(shares[i])
	}
	return shares, nil
}

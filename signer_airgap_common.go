// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hsm

import (
	"context"
	"errors"
	"fmt"
)

// airgappedSign is the common driver shared by every airgapped hardware
// wallet signer (Coldcard, Foundation Passport, Keystone Pro, NGRAVE
// Zero). It builds an AirgapChallenge using the per-device encoder,
// hands it to the configured AirgapTransport, and decodes the response.
//
// The function blocks for the full duration of the human ceremony. The
// caller's context is propagated to both DisplayChallenge and
// AwaitResponse so timeouts and cancellation work as expected.
func airgappedSign(
	ctx context.Context,
	transport AirgapTransport,
	deviceID string,
	encode func(message []byte, sessionID string) (AirgapChallenge, error),
	decode func(response []byte) ([]byte, error),
	message []byte,
) ([]byte, error) {
	if transport == nil {
		return nil, ErrAirgapTransportRequired
	}
	if len(message) == 0 {
		return nil, errors.New("hsm/airgap: empty message")
	}
	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}
	challenge, err := encode(message, sessionID)
	if err != nil {
		return nil, fmt.Errorf("hsm/airgap: encode challenge: %w", err)
	}
	challenge.DeviceID = deviceID
	challenge.SessionID = sessionID

	if err := transport.DisplayChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("hsm/airgap: display: %w", err)
	}
	resp, err := transport.AwaitResponse(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("hsm/airgap: await: %w", err)
	}
	if len(resp) == 0 {
		return nil, ErrAirgapResponseInvalid
	}
	sig, err := decode(resp)
	if err != nil {
		return nil, fmt.Errorf("hsm/airgap: decode response: %w", err)
	}
	return sig, nil
}

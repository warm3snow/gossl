// SPDX-License-Identifier: Apache-2.0

package gmcredentials

import tls "github.com/warm3snow/gossl/crypto/gmtls"

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

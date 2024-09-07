/**
 * @Author: xueyanghan
 * @File: hash.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/7 09:31
 */

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strconv"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	"github.com/tjfoc/gmsm/sm3"
)

// Hash identifies a cryptographic hash function that is implemented in another
// package.
type Hash uint

var hashes = make([]func() hash.Hash, maxHash)

// HashFunc simply returns the value of h so that Hash implements SignerOpts.
func (h Hash) HashFunc() Hash {
	return h
}

func init() {
	hashes[MD4] = md4.New
	hashes[MD5] = md5.New
	hashes[SHA1] = sha1.New
	hashes[SHA224] = sha256.New224
	hashes[SHA256] = sha256.New
	hashes[SHA384] = sha512.New384
	hashes[SHA512] = sha512.New
	//hashes[MD5SHA1] = md5.New
	hashes[RIPEMD160] = ripemd160.New
	hashes[SHA3_224] = sha3.New224
	hashes[SHA3_256] = sha3.New256
	hashes[SHA3_512] = sha3.New512
	hashes[SHA512_224] = sha512.New512_224
	hashes[SHA512_256] = sha512.New512_256
	//blake2snew, _ := blake2s.New256(nil)
	hashes[BLAKE2s_256] = func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}
	hashes[BLAKE2b_256] = func() hash.Hash {
		h, _ := blake2b.New256(nil)
		return h
	}
	hashes[BLAKE2b_384] = func() hash.Hash {
		h, _ := blake2b.New384(nil)
		return h
	}
	hashes[BLAKE2b_512] = func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}
	hashes[SM3] = sm3.New
}

const (
	MD4         Hash = 1 + iota // import golang.org/x/crypto/md4
	MD5                         // import crypto/md5
	SHA1                        // import crypto/sha1
	SHA224                      // import crypto/sha256
	SHA256                      // import crypto/sha256
	SHA384                      // import crypto/sha512
	SHA512                      // import crypto/sha512
	MD5SHA1                     // no implementation; MD5+SHA1 used for TLS RSA
	RIPEMD160                   // import golang.org/x/crypto/ripemd160
	SHA3_224                    // import golang.org/x/crypto/sha3
	SHA3_256                    // import golang.org/x/crypto/sha3
	SHA3_384                    // import golang.org/x/crypto/sha3
	SHA3_512                    // import golang.org/x/crypto/sha3
	SHA512_224                  // import crypto/sha512
	SHA512_256                  // import crypto/sha512
	BLAKE2s_256                 // import golang.org/x/crypto/blake2s
	BLAKE2b_256                 // import golang.org/x/crypto/blake2b
	BLAKE2b_384                 // import golang.org/x/crypto/blake2b
	BLAKE2b_512                 // import golang.org/x/crypto/blake2b
	SM3
	maxHash
)

var digestSizes = []uint8{
	MD4:         16,
	MD5:         16,
	SHA1:        20,
	SHA224:      28,
	SHA256:      32,
	SHA384:      48,
	SHA512:      64,
	SHA512_224:  28,
	SHA512_256:  32,
	SHA3_224:    28,
	SHA3_256:    32,
	SHA3_384:    48,
	SHA3_512:    64,
	MD5SHA1:     36,
	RIPEMD160:   20,
	BLAKE2s_256: 32,
	BLAKE2b_256: 32,
	BLAKE2b_384: 48,
	BLAKE2b_512: 64,
	SM3:         32,
}

// Size returns the length, in bytes, of a digest resulting from the given hash
// function. It doesn't require that the hash function in question be linked
// into the program.
func (h Hash) Size() int {
	if h > 0 && h < maxHash {
		return int(digestSizes[h])
	}
	panic("crypto: Size of unknown hash function")
}

// New returns a new hash.Hash calculating the given hash function. New panics
// if the hash function is not linked into the binary.
func (h Hash) New() hash.Hash {
	if h > 0 && h < maxHash {
		f := hashes[h]
		if f != nil {
			return f()
		}
	}
	panic("crypto: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable")
}

// Available reports whether the given hash function is linked into the binary.
func (h Hash) Available() bool {
	return h < maxHash && hashes[h] != nil
}

// RegisterHash registers a function that returns a new instance of the given
// hash function. This is intended to be called from the init function in
// packages that implement hash functions.
func RegisterHash(h Hash, f func() hash.Hash) {
	if h >= maxHash {
		panic("crypto: RegisterHash of unknown hash function")
	}
	hashes[h] = f
}

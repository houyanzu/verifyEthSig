package verifyEthSig

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
	"strings"
)

func Verify(data, addr, signature string) (bool, error)  {
	if len(signature) != 132 {
		return false, fmt.Errorf("signature must be 65 bytes long")
	}
	sig, err := hexutil.Decode(signature)
	if err != nil {
		return false, err
	}
	if sig[64] != 27 && sig[64] != 28 {
		return false, fmt.Errorf("invalid Ethereum signature (V is not 27 or 28)")
	}
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	rpk, err := crypto.Ecrecover(signStrHash(data), sig)
	if err != nil {
		return false, err
	}
	has := sha3.NewLegacyKeccak256()
	has.Write(rpk[1:])
	sigAddr := hexutil.Encode(has.Sum(nil)[12:])
	return strings.ToLower(sigAddr) == strings.ToLower(addr), nil
}

func VerifyHashSig(data []byte, addr, signature string) (bool, error) {
	if len(signature) != 132 {
		return false, fmt.Errorf("signature must be 65 bytes long")
	}
	sig, err := hexutil.Decode(signature)
	if err != nil {
		return false, err
	}
	if sig[64] != 27 && sig[64] != 28 {
		return false, fmt.Errorf("invalid Ethereum signature (V is not 27 or 28)")
	}
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	rpk, err := crypto.Ecrecover(signByteHash(data), sig)
	if err != nil {
		return false, err
	}
	has := sha3.NewLegacyKeccak256()
	has.Write(rpk[1:])
	sigAddr := hexutil.Encode(has.Sum(nil)[12:])
	return strings.ToLower(sigAddr) == strings.ToLower(addr), nil
}

func signByteHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(data))
	hs := crypto.Keccak256([]byte(msg), data)
	return hs
}

func signStrHash(data string) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	hs := crypto.Keccak256([]byte(msg))

	return hs
}

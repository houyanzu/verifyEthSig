package verifyEthSig

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func SignHash(hash []byte, priKey string) (sigStr string, err error) {
	signature, err := SignHashGetBytes(hash, priKey)
	if err != nil {
		return
	}
	sigStr = hexutil.Encode(signature)
	return
}

func SignHashGetBytes(hash []byte, priKey string) (signature []byte, err error) {
	privateKey, err := crypto.HexToECDSA(priKey)
	if err != nil {
		return
	}
	hash = signByteHash(hash)

	signature, err = crypto.Sign(hash, privateKey)
	if err != nil {
		return
	}
	signature[64] += 27
	return
}

func DecodeSignature(signatureBytes []byte) (r [32]byte, s [32]byte, v byte, err error) {
	if len(signatureBytes) != 65 {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("invalid signature length")
	}

	// 提取 R, S, V
	copy(r[:], signatureBytes[:32])
	copy(s[:], signatureBytes[32:64])
	v = signatureBytes[64]

	return r, s, v, nil
}

func DecodeSignatureHex(signatureHex string) (r [32]byte, s [32]byte, v byte, err error) {
	signatureBytes, err := hexutil.Decode(signatureHex)
	if err != nil {
		return
	}

	return DecodeSignature(signatureBytes)
}

func SignStr(data, priKey string) (sigStr string, err error) {
	signature, err := SignStrGetBytes(data, priKey)
	if err != nil {
		return
	}
	return hexutil.Encode(signature), nil
}

func SignStrGetBytes(data, priKey string) (signature []byte, err error) {
	privateKey, err := crypto.HexToECDSA(priKey)
	if err != nil {
		return
	}
	hash := signStrHash(data)

	signature, err = crypto.Sign(hash, privateKey)
	if err != nil {
		return
	}
	signature[64] += 27
	return
}

package verifyEthSig

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func SignHash(hash []byte, priKey string) (sigStr string, err error) {
	privateKey, err := crypto.HexToECDSA(priKey)
	if err != nil {
		return
	}
	hash = signByteHash(hash)

	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return
	}
	signature[64] += 27
	return hexutil.Encode(signature), nil
}

func SignStr(data, priKey string) (sigStr string, err error) {
	privateKey, err := crypto.HexToECDSA(priKey)
	if err != nil {
		return
	}
	hash := signStrHash(data)

	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return
	}
	signature[64] += 27
	return hexutil.Encode(signature), nil
}

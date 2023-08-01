package verifyEthSig

import (
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"testing"
)

const sig1 = "0x6d6d08f28e501a5dbf96f303da9a50df87065ca8022b1d9f8eb632ab5d7c27472530c25f0bfbd2567ccc5d702afe4b1b1795f97d072bb087e203ebbb1bef21421c"
const data = "b2bbbe395bb9e4e3928923802d0d80c8d329c48970d3aa1398651f994317b360"
const addr = "0x2F9c946f4f061505Af0669F9E3e2e8Dd6dCD8B17"
const priKey2 = "6efef37df82d19ccf2f151ccb1a6b9db5909b19f7ac0d6072e6c0d26c75ea61c"
const addr2 = "0xB7Ae3475CaF9a94c44C2d7696ea3AF836076F934"

func TestVerify(t *testing.T) {
	fmt.Println(Verify(data, addr, sig1))
}

func Test(t *testing.T) {
	privateKey, err := crypto.HexToECDSA(priKey2)
	if err != nil {
		// 处理错误
	}

	data1 := []byte("hello")
	hash := crypto.Keccak256Hash(data1)
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		// 处理错误
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	v := uint8(signature[64]) + 27
	fmt.Println("r:", r)
	fmt.Println("s:", s)
	fmt.Println("v:", v)
}

package verifyEthSig

import (
	"fmt"
	"testing"
)

const sig1 = "0x6d6d08f28e501a5dbf96f303da9a50df87065ca8022b1d9f8eb632ab5d7c27472530c25f0bfbd2567ccc5d702afe4b1b1795f97d072bb087e203ebbb1bef21421c"
const data = "b2bbbe395bb9e4e3928923802d0d80c8d329c48970d3aa1398651f994317b360"
const addr = "0x2F9c946f4f061505Af0669F9E3e2e8Dd6dCD8B17"

func TestVerify(t *testing.T) {
	fmt.Println(Verify(data, addr, sig1))
}
package randomx

import (
	"crypto/rand"
	"math"
	mrand "math/rand"
)

func RandomBytes(size int) []byte {
	byte := make([]byte, size)
	rand.Read(byte)
	return byte
}

func RandomStringsChoice(data []string) string {
	return data[mrand.Intn(len(data))]
}

func RandomIntChoice(data []int) int {
	return data[mrand.Intn(len(data))]
}

// Generate random integer between min and max
func RandIntRange(min, max int) int {
	if min == max {
		return min
	}
	return mrand.Intn((max+1)-min) + min
}

func RandFloat64Range(min, max float64) float64 {
	if min == max {
		return min
	}
	return mrand.Float64()*(max-min) + min
}

// Uint8 will generate a random uint8 value
func Uint8() uint8 {
	return uint8(RandIntRange(0, math.MaxUint8))
}

// Uint16 will generate a random uint16 value
func Uint16() uint16 {
	return uint16(RandIntRange(0, math.MaxUint16))
}

// Float64 will generate a random float64 value
func Float64() float64 {
	return RandFloat64Range(math.SmallestNonzeroFloat64, math.MaxFloat64)
}

// Float64Range will generate a random float64 value between min and max
func Float64Range(min, max float64) float64 {
	return RandFloat64Range(min, max)
}

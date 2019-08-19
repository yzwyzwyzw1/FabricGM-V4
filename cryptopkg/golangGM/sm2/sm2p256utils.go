/*
编写者:严志伟
编写时间:2018/08/01
公司:中国搜索信息科技股份有限公司

*/

package sm2

import "math/big"

var sm2P256Carry = [8 * 9]uint32{
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x2, 0x0, 0x1FFFFF00, 0x7FF, 0x0, 0x0, 0x0, 0x2000000, 0x0,
	0x4, 0x0, 0x1FFFFE00, 0xFFF, 0x0, 0x0, 0x0, 0x4000000, 0x0,
	0x6, 0x0, 0x1FFFFD00, 0x17FF, 0x0, 0x0, 0x0, 0x6000000, 0x0,
	0x8, 0x0, 0x1FFFFC00, 0x1FFF, 0x0, 0x0, 0x0, 0x8000000, 0x0,
	0xA, 0x0, 0x1FFFFB00, 0x27FF, 0x0, 0x0, 0x0, 0xA000000, 0x0,
	0xC, 0x0, 0x1FFFFA00, 0x2FFF, 0x0, 0x0, 0x0, 0xC000000, 0x0,
	0xE, 0x0, 0x1FFFF900, 0x37FF, 0x0, 0x0, 0x0, 0xE000000, 0x0,
}

var sm2P256Factor = []sm2P256FieldElement{
	sm2P256FieldElement{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
	sm2P256FieldElement{0x2, 0x0, 0x1FFFFF00, 0x7FF, 0x0, 0x0, 0x0, 0x2000000, 0x0},
	sm2P256FieldElement{0x4, 0x0, 0x1FFFFE00, 0xFFF, 0x0, 0x0, 0x0, 0x4000000, 0x0},
	sm2P256FieldElement{0x6, 0x0, 0x1FFFFD00, 0x17FF, 0x0, 0x0, 0x0, 0x6000000, 0x0},
	sm2P256FieldElement{0x8, 0x0, 0x1FFFFC00, 0x1FFF, 0x0, 0x0, 0x0, 0x8000000, 0x0},
	sm2P256FieldElement{0xA, 0x0, 0x1FFFFB00, 0x27FF, 0x0, 0x0, 0x0, 0xA000000, 0x0},
	sm2P256FieldElement{0xC, 0x0, 0x1FFFFA00, 0x2FFF, 0x0, 0x0, 0x0, 0xC000000, 0x0},
	sm2P256FieldElement{0xE, 0x0, 0x1FFFF900, 0x37FF, 0x0, 0x0, 0x0, 0xE000000, 0x0},
	sm2P256FieldElement{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01},
}

// p256Zero31 is 0 mod p.
var sm2P256Zero31 = sm2P256FieldElement{0x7FFFFFF8, 0x3FFFFFFC, 0x800003FC, 0x3FFFDFFC, 0x7FFFFFFC, 0x3FFFFFFC, 0x7FFFFFFC, 0x37FFFFFC, 0x7FFFFFFC}



type sm2P256FieldElement [9]uint32
type sm2P256LargeFieldElement [17]uint64

//p256椭圆曲线工具类
type sm2P256Util struct{


}
// p256Mul sets out=in*in2.
//
// On entry: in[0,2,...] < 2**30, in[1,3,...] < 2**29 and
//           in2[0,2,...] < 2**30, in2[1,3,...] < 2**29.
// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
func (util sm2P256Util)p256Mul(out, in, in2 *sm2P256FieldElement) {
	var tmp sm2P256LargeFieldElement

	tmp[0] = uint64(in[0]) * uint64(in2[0])
	tmp[1] = uint64(in[0])*(uint64(in2[1])<<0) +
		uint64(in[1])*(uint64(in2[0])<<0)
	tmp[2] = uint64(in[0])*(uint64(in2[2])<<0) +
		uint64(in[1])*(uint64(in2[1])<<1) +
		uint64(in[2])*(uint64(in2[0])<<0)
	tmp[3] = uint64(in[0])*(uint64(in2[3])<<0) +
		uint64(in[1])*(uint64(in2[2])<<0) +
		uint64(in[2])*(uint64(in2[1])<<0) +
		uint64(in[3])*(uint64(in2[0])<<0)
	tmp[4] = uint64(in[0])*(uint64(in2[4])<<0) +
		uint64(in[1])*(uint64(in2[3])<<1) +
		uint64(in[2])*(uint64(in2[2])<<0) +
		uint64(in[3])*(uint64(in2[1])<<1) +
		uint64(in[4])*(uint64(in2[0])<<0)
	tmp[5] = uint64(in[0])*(uint64(in2[5])<<0) +
		uint64(in[1])*(uint64(in2[4])<<0) +
		uint64(in[2])*(uint64(in2[3])<<0) +
		uint64(in[3])*(uint64(in2[2])<<0) +
		uint64(in[4])*(uint64(in2[1])<<0) +
		uint64(in[5])*(uint64(in2[0])<<0)
	tmp[6] = uint64(in[0])*(uint64(in2[6])<<0) +
		uint64(in[1])*(uint64(in2[5])<<1) +
		uint64(in[2])*(uint64(in2[4])<<0) +
		uint64(in[3])*(uint64(in2[3])<<1) +
		uint64(in[4])*(uint64(in2[2])<<0) +
		uint64(in[5])*(uint64(in2[1])<<1) +
		uint64(in[6])*(uint64(in2[0])<<0)
	tmp[7] = uint64(in[0])*(uint64(in2[7])<<0) +
		uint64(in[1])*(uint64(in2[6])<<0) +
		uint64(in[2])*(uint64(in2[5])<<0) +
		uint64(in[3])*(uint64(in2[4])<<0) +
		uint64(in[4])*(uint64(in2[3])<<0) +
		uint64(in[5])*(uint64(in2[2])<<0) +
		uint64(in[6])*(uint64(in2[1])<<0) +
		uint64(in[7])*(uint64(in2[0])<<0)
	// tmp[8] has the greatest value but doesn't overflow. See logic in
	// p256Square.
	tmp[8] = uint64(in[0])*(uint64(in2[8])<<0) +
		uint64(in[1])*(uint64(in2[7])<<1) +
		uint64(in[2])*(uint64(in2[6])<<0) +
		uint64(in[3])*(uint64(in2[5])<<1) +
		uint64(in[4])*(uint64(in2[4])<<0) +
		uint64(in[5])*(uint64(in2[3])<<1) +
		uint64(in[6])*(uint64(in2[2])<<0) +
		uint64(in[7])*(uint64(in2[1])<<1) +
		uint64(in[8])*(uint64(in2[0])<<0)
	tmp[9] = uint64(in[1])*(uint64(in2[8])<<0) +
		uint64(in[2])*(uint64(in2[7])<<0) +
		uint64(in[3])*(uint64(in2[6])<<0) +
		uint64(in[4])*(uint64(in2[5])<<0) +
		uint64(in[5])*(uint64(in2[4])<<0) +
		uint64(in[6])*(uint64(in2[3])<<0) +
		uint64(in[7])*(uint64(in2[2])<<0) +
		uint64(in[8])*(uint64(in2[1])<<0)
	tmp[10] = uint64(in[2])*(uint64(in2[8])<<0) +
		uint64(in[3])*(uint64(in2[7])<<1) +
		uint64(in[4])*(uint64(in2[6])<<0) +
		uint64(in[5])*(uint64(in2[5])<<1) +
		uint64(in[6])*(uint64(in2[4])<<0) +
		uint64(in[7])*(uint64(in2[3])<<1) +
		uint64(in[8])*(uint64(in2[2])<<0)
	tmp[11] = uint64(in[3])*(uint64(in2[8])<<0) +
		uint64(in[4])*(uint64(in2[7])<<0) +
		uint64(in[5])*(uint64(in2[6])<<0) +
		uint64(in[6])*(uint64(in2[5])<<0) +
		uint64(in[7])*(uint64(in2[4])<<0) +
		uint64(in[8])*(uint64(in2[3])<<0)
	tmp[12] = uint64(in[4])*(uint64(in2[8])<<0) +
		uint64(in[5])*(uint64(in2[7])<<1) +
		uint64(in[6])*(uint64(in2[6])<<0) +
		uint64(in[7])*(uint64(in2[5])<<1) +
		uint64(in[8])*(uint64(in2[4])<<0)
	tmp[13] = uint64(in[5])*(uint64(in2[8])<<0) +
		uint64(in[6])*(uint64(in2[7])<<0) +
		uint64(in[7])*(uint64(in2[6])<<0) +
		uint64(in[8])*(uint64(in2[5])<<0)
	tmp[14] = uint64(in[6])*(uint64(in2[8])<<0) +
		uint64(in[7])*(uint64(in2[7])<<1) +
		uint64(in[8])*(uint64(in2[6])<<0)
	tmp[15] = uint64(in[7])*(uint64(in2[8])<<0) +
		uint64(in[8])*(uint64(in2[7])<<0)
	tmp[16] = uint64(in[8]) * (uint64(in2[8]) << 0)

	sm2util:=sm2P256Util{}
	sm2util.p256ReduceDegree(out, &tmp)
}

// b = a * a
func  (util sm2P256Util)p256Square(b, a *sm2P256FieldElement) {
	var tmp sm2P256LargeFieldElement//最大域元素

	tmp[0] = uint64(a[0]) * uint64(a[0])
	tmp[1] = uint64(a[0]) * (uint64(a[1]) << 1)
	tmp[2] = uint64(a[0])*(uint64(a[2])<<1) +
		uint64(a[1])*(uint64(a[1])<<1)
	tmp[3] = uint64(a[0])*(uint64(a[3])<<1) +
		uint64(a[1])*(uint64(a[2])<<1)
	tmp[4] = uint64(a[0])*(uint64(a[4])<<1) +
		uint64(a[1])*(uint64(a[3])<<2) +
		uint64(a[2])*uint64(a[2])
	tmp[5] = uint64(a[0])*(uint64(a[5])<<1) +
		uint64(a[1])*(uint64(a[4])<<1) +
		uint64(a[2])*(uint64(a[3])<<1)
	tmp[6] = uint64(a[0])*(uint64(a[6])<<1) +
		uint64(a[1])*(uint64(a[5])<<2) +
		uint64(a[2])*(uint64(a[4])<<1) +
		uint64(a[3])*(uint64(a[3])<<1)
	tmp[7] = uint64(a[0])*(uint64(a[7])<<1) +
		uint64(a[1])*(uint64(a[6])<<1) +
		uint64(a[2])*(uint64(a[5])<<1) +
		uint64(a[3])*(uint64(a[4])<<1)
	// tmp[8] has the greatest value of 2**61 + 2**60 + 2**61 + 2**60 + 2**60,
	// which is < 2**64 as required.
	tmp[8] = uint64(a[0])*(uint64(a[8])<<1) +
		uint64(a[1])*(uint64(a[7])<<2) +
		uint64(a[2])*(uint64(a[6])<<1) +
		uint64(a[3])*(uint64(a[5])<<2) +
		uint64(a[4])*uint64(a[4])
	tmp[9] = uint64(a[1])*(uint64(a[8])<<1) +
		uint64(a[2])*(uint64(a[7])<<1) +
		uint64(a[3])*(uint64(a[6])<<1) +
		uint64(a[4])*(uint64(a[5])<<1)
	tmp[10] = uint64(a[2])*(uint64(a[8])<<1) +
		uint64(a[3])*(uint64(a[7])<<2) +
		uint64(a[4])*(uint64(a[6])<<1) +
		uint64(a[5])*(uint64(a[5])<<1)
	tmp[11] = uint64(a[3])*(uint64(a[8])<<1) +
		uint64(a[4])*(uint64(a[7])<<1) +
		uint64(a[5])*(uint64(a[6])<<1)
	tmp[12] = uint64(a[4])*(uint64(a[8])<<1) +
		uint64(a[5])*(uint64(a[7])<<2) +
		uint64(a[6])*uint64(a[6])
	tmp[13] = uint64(a[5])*(uint64(a[8])<<1) +
		uint64(a[6])*(uint64(a[7])<<1)
	tmp[14] = uint64(a[6])*(uint64(a[8])<<1) +
		uint64(a[7])*(uint64(a[7])<<1)
	tmp[15] = uint64(a[7]) * (uint64(a[8]) << 1)
	tmp[16] = uint64(a[8]) * uint64(a[8])

	sm2util:=sm2P256Util{}
	sm2util.p256ReduceDegree(b, &tmp)
}


// c = a + b
func (util sm2P256Util)p256Add(c, a, b *sm2P256FieldElement) {
	carry := uint32(0)
	for i := 0; ; i++ {
		c[i] = a[i] + b[i]
		c[i] += carry
		carry = c[i] >> 29
		c[i] &= bottom29Bits
		i++
		if i == 9 {
			break
		}
		c[i] = a[i] + b[i]
		c[i] += carry
		carry = c[i] >> 28
		c[i] &= bottom28Bits
	}
	sm2util:=sm2P256Util{}
	sm2util.p256ReduceCarry(c, carry)
}

// carry < 2 ^ 3
func (util sm2P256Util)p256ReduceCarry(a *sm2P256FieldElement, carry uint32) {
	a[0] += sm2P256Carry[carry*9+0]
	a[2] += sm2P256Carry[carry*9+2]
	a[3] += sm2P256Carry[carry*9+3]
	a[7] += sm2P256Carry[carry*9+7]
}


// p256ReduceDegree sets out = tmp/R mod p where tmp contains 64-bit words with
// the same 29,28,... bit positions as an field element.
//
// The values in field elements are in Montgomery form: x*R mod p where R =
// 2**257. Since we just multiplied two Montgomery values together, the result
// is x*y*R*R mod p. We wish to divide by R in order for the result also to be
// in Montgomery form.
//
// On entry: tmp[i] < 2**64
// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29
func (util sm2P256Util)p256ReduceDegree(a *sm2P256FieldElement, b *sm2P256LargeFieldElement) {
	var tmp [18]uint32
	var carry, x, xMask uint32

	// tmp
	// 0  | 1  | 2  | 3  | 4  | 5  | 6  | 7  | 8  |  9 | 10 ...
	// 29 | 28 | 29 | 28 | 29 | 28 | 29 | 28 | 29 | 28 | 29 ...
	tmp[0] = uint32(b[0]) & bottom29Bits
	tmp[1] = uint32(b[0]) >> 29
	tmp[1] |= (uint32(b[0]>>32) << 3) & bottom28Bits
	tmp[1] += uint32(b[1]) & bottom28Bits
	carry = tmp[1] >> 28
	tmp[1] &= bottom28Bits
	for i := 2; i < 17; i++ {
		tmp[i] = (uint32(b[i-2] >> 32)) >> 25
		tmp[i] += (uint32(b[i-1])) >> 28
		tmp[i] += (uint32(b[i-1]>>32) << 4) & bottom29Bits
		tmp[i] += uint32(b[i]) & bottom29Bits
		tmp[i] += carry
		carry = tmp[i] >> 29
		tmp[i] &= bottom29Bits

		i++
		if i == 17 {
			break
		}
		tmp[i] = uint32(b[i-2]>>32) >> 25
		tmp[i] += uint32(b[i-1]) >> 29
		tmp[i] += ((uint32(b[i-1] >> 32)) << 3) & bottom28Bits
		tmp[i] += uint32(b[i]) & bottom28Bits
		tmp[i] += carry
		carry = tmp[i] >> 28
		tmp[i] &= bottom28Bits
	}
	tmp[17] = uint32(b[15]>>32) >> 25
	tmp[17] += uint32(b[16]) >> 29
	tmp[17] += uint32(b[16]>>32) << 3
	tmp[17] += carry

	for i := 0; ; i += 2 {

		tmp[i+1] += tmp[i] >> 29
		x = tmp[i] & bottom29Bits
		tmp[i] = 0
		if x > 0 {
			set4 := uint32(0)
			set7 := uint32(0)
			xMask = nonZeroToAllOnes(x)
			tmp[i+2] += (x << 7) & bottom29Bits
			tmp[i+3] += x >> 22
			if tmp[i+3] < 0x10000000 {
				set4 = 1
				tmp[i+3] += 0x10000000 & xMask
				tmp[i+3] -= (x << 10) & bottom28Bits
			} else {
				tmp[i+3] -= (x << 10) & bottom28Bits
			}
			if tmp[i+4] < 0x20000000 {
				tmp[i+4] += 0x20000000 & xMask
				tmp[i+4] -= set4 // 借位
				tmp[i+4] -= x >> 18
				if tmp[i+5] < 0x10000000 {
					tmp[i+5] += 0x10000000 & xMask
					tmp[i+5] -= 1 // 借位
					if tmp[i+6] < 0x20000000 {
						set7 = 1
						tmp[i+6] += 0x20000000 & xMask
						tmp[i+6] -= 1 // 借位
					} else {
						tmp[i+6] -= 1 // 借位
					}
				} else {
					tmp[i+5] -= 1
				}
			} else {
				tmp[i+4] -= set4 // 借位
				tmp[i+4] -= x >> 18
			}
			if tmp[i+7] < 0x10000000 {
				tmp[i+7] += 0x10000000 & xMask
				tmp[i+7] -= set7
				tmp[i+7] -= (x << 24) & bottom28Bits
				tmp[i+8] += (x << 28) & bottom29Bits
				if tmp[i+8] < 0x20000000 {
					tmp[i+8] += 0x20000000 & xMask
					tmp[i+8] -= 1
					tmp[i+8] -= x >> 4
					tmp[i+9] += ((x >> 1) - 1) & xMask
				} else {
					tmp[i+8] -= 1
					tmp[i+8] -= x >> 4
					tmp[i+9] += (x >> 1) & xMask
				}
			} else {
				tmp[i+7] -= set7 // 借位
				tmp[i+7] -= (x << 24) & bottom28Bits
				tmp[i+8] += (x << 28) & bottom29Bits
				if tmp[i+8] < 0x20000000 {
					tmp[i+8] += 0x20000000 & xMask
					tmp[i+8] -= x >> 4
					tmp[i+9] += ((x >> 1) - 1) & xMask
				} else {
					tmp[i+8] -= x >> 4
					tmp[i+9] += (x >> 1) & xMask
				}
			}

		}

		if i+1 == 9 {
			break
		}

		tmp[i+2] += tmp[i+1] >> 28
		x = tmp[i+1] & bottom28Bits
		tmp[i+1] = 0
		if x > 0 {
			set5 := uint32(0)
			set8 := uint32(0)
			set9 := uint32(0)
			xMask = nonZeroToAllOnes(x)
			tmp[i+3] += (x << 7) & bottom28Bits
			tmp[i+4] += x >> 21
			if tmp[i+4] < 0x20000000 {
				set5 = 1
				tmp[i+4] += 0x20000000 & xMask
				tmp[i+4] -= (x << 11) & bottom29Bits
			} else {
				tmp[i+4] -= (x << 11) & bottom29Bits
			}
			if tmp[i+5] < 0x10000000 {
				tmp[i+5] += 0x10000000 & xMask
				tmp[i+5] -= set5 // 借位
				tmp[i+5] -= x >> 18
				if tmp[i+6] < 0x20000000 {
					tmp[i+6] += 0x20000000 & xMask
					tmp[i+6] -= 1 // 借位
					if tmp[i+7] < 0x10000000 {
						set8 = 1
						tmp[i+7] += 0x10000000 & xMask
						tmp[i+7] -= 1 // 借位
					} else {
						tmp[i+7] -= 1 // 借位
					}
				} else {
					tmp[i+6] -= 1 // 借位
				}
			} else {
				tmp[i+5] -= set5 // 借位
				tmp[i+5] -= x >> 18
			}
			if tmp[i+8] < 0x20000000 {
				set9 = 1
				tmp[i+8] += 0x20000000 & xMask
				tmp[i+8] -= set8
				tmp[i+8] -= (x << 25) & bottom29Bits
			} else {
				tmp[i+8] -= set8
				tmp[i+8] -= (x << 25) & bottom29Bits
			}
			if tmp[i+9] < 0x10000000 {
				tmp[i+9] += 0x10000000 & xMask
				tmp[i+9] -= set9 // 借位
				tmp[i+9] -= x >> 4
				tmp[i+10] += (x - 1) & xMask
			} else {
				tmp[i+9] -= set9 // 借位
				tmp[i+9] -= x >> 4
				tmp[i+10] += x & xMask
			}
		}
	}

	carry = uint32(0)
	for i := 0; i < 8; i++ {
		a[i] = tmp[i+9]
		a[i] += carry
		a[i] += (tmp[i+10] << 28) & bottom29Bits
		carry = a[i] >> 29
		a[i] &= bottom29Bits

		i++
		a[i] = tmp[i+9] >> 1
		a[i] += carry
		carry = a[i] >> 28
		a[i] &= bottom28Bits
	}
	a[8] = tmp[17]
	a[8] += carry
	carry = a[8] >> 29
	a[8] &= bottom29Bits

	sm2util:=sm2P256Util{}
	sm2util.p256ReduceCarry(a, carry)
}

// nonZeroToAllOnes returns:
//   0xffffffff for 0 < x <= 2**31
//   0 for x == 0 or x > 2**31.
func nonZeroToAllOnes(x uint32) uint32 {
	return ((x - 1) >> 31) - 1
}

// (x3, y3, z3) = (x1, y1, z1) + (x2, y2, z2)
func (util sm2P256Util)p256PointAdd(x1, y1, z1, x2, y2, z2, x3, y3, z3 *sm2P256FieldElement) {
	var u1, u2, z22, z12, z23, z13, s1, s2, h, h2, r, r2, tm sm2P256FieldElement

	sm2util := sm2P256Util{}
	if sm2util.p256ToBig(z1).Sign() == 0 {
		sm2util.p256Dup(x3, x2)
		sm2util.p256Dup(y3, y2)
		sm2util.p256Dup(z3, z2)
		return
	}

	if sm2util.p256ToBig(z2).Sign() == 0 {
		sm2util.p256Dup(x3, x1)
		sm2util.p256Dup(y3, y1)
		sm2util.p256Dup(z3, z1)
		return
	}

	sm2util.p256Square(&z12, z1) // z12 = z1 ^ 2
	sm2util.p256Square(&z22, z2) // z22 = z2 ^ 2

	sm2util.p256Mul(&z13, &z12, z1) // z13 = z1 ^ 3
	sm2util.p256Mul(&z23, &z22, z2) // z23 = z2 ^ 3

	sm2util.p256Mul(&u1, x1, &z22) // u1 = x1 * z2 ^ 2
	sm2util.p256Mul(&u2, x2, &z12) // u2 = x2 * z1 ^ 2

	sm2util.p256Mul(&s1, y1, &z23) // s1 = y1 * z2 ^ 3
	sm2util.p256Mul(&s2, y2, &z13) // s2 = y2 * z1 ^ 3

	if sm2util.p256ToBig(&u1).Cmp(sm2util.p256ToBig(&u2)) == 0 &&
		sm2util.p256ToBig(&s1).Cmp(sm2util.p256ToBig(&s2)) == 0 {
		sm2util.p256PointDouble(x1, y1, z1, x1, y1, z1)
	}

	sm2util.p256Sub(&h, &u2, &u1) // h = u2 - u1
	sm2util.p256Sub(&r, &s2, &s1) // r = s2 - s1

	sm2util.p256Square(&r2, &r) // r2 = r ^ 2
	sm2util.p256Square(&h2, &h) // h2 = h ^ 2

	sm2util.p256Mul(&tm, &h2, &h) // tm = h ^ 3
	sm2util.p256Sub(x3, &r2, &tm)
	sm2util.p256Mul(&tm, &u1, &h2)
	sm2util.p256Scalar(&tm, 2)   // tm = 2 * (u1 * h ^ 2)
	sm2util.p256Sub(x3, x3, &tm) // x3 = r ^ 2 - h ^ 3 - 2 * u1 * h ^ 2

	sm2util.p256Mul(&tm, &u1, &h2) // tm = u1 * h ^ 2
	sm2util.p256Sub(&tm, &tm, x3)  // tm = u1 * h ^ 2 - x3
	sm2util.p256Mul(y3, &r, &tm)
	sm2util.p256Mul(&tm, &h2, &h)  // tm = h ^ 3
	sm2util.p256Mul(&tm, &tm, &s1) // tm = s1 * h ^ 3
	sm2util.p256Sub(y3, y3, &tm)   // y3 = r * (u1 * h ^ 2 - x3) - s1 * h ^ 3

	sm2util.p256Mul(z3, z1, z2)
	sm2util.p256Mul(z3, z3, &h) // z3 = z1 * z3 * h
}

func (util sm2P256Util)p256PointDouble(x3, y3, z3, x, y, z *sm2P256FieldElement) {
	var s, m, m2, x2, y2, z2, z4, y4, az4 sm2P256FieldElement

	sm2util := sm2P256Util{}
	sm2util.p256Square(&x2, x) // x2 = x ^ 2
	sm2util.p256Square(&y2, y) // y2 = y ^ 2
	sm2util.p256Square(&z2, z) // z2 = z ^ 2

	sm2util.p256Square(&z4, z)   // z4 = z ^ 2
	sm2util.p256Mul(&z4, &z4, z) // z4 = z ^ 3
	sm2util.p256Mul(&z4, &z4, z) // z4 = z ^ 4

	sm2util.p256Square(&y4, y)   // y4 = y ^ 2
	sm2util.p256Mul(&y4, &y4, y) // y4 = y ^ 3
	sm2util.p256Mul(&y4, &y4, y) // y4 = y ^ 4
	sm2util.p256Scalar(&y4, 8)   // y4 = 8 * y ^ 4

	sm2util.p256Mul(&s, x, &y2)
	sm2util.p256Scalar(&s, 4) // s = 4 * x * y ^ 2

	sm2util.p256Dup(&m, &x2)
	sm2util.p256Scalar(&m, 3)
	sm2util.p256Mul(&az4, &sm2p256Params.a, &z4)
	sm2util.p256Add(&m, &m, &az4) // m = 3 * x ^ 2 + a * z ^ 4

	sm2util.p256Square(&m2, &m) // m2 = m ^ 2

	sm2util.p256Add(z3, y, z)
	sm2util.p256Square(z3, z3)
	sm2util.p256Sub(z3, z3, &z2)
	sm2util.p256Sub(z3, z3, &y2) // z' = (y + z) ^2 - z ^ 2 - y ^ 2

	sm2util.p256Sub(x3, &m2, &s)
	sm2util.p256Sub(x3, x3, &s) // x' = m2 - 2 * s

	sm2util.p256Sub(y3, &s, x3)
	sm2util.p256Mul(y3, y3, &m)
	sm2util.p256Sub(y3, y3, &y4) // y' = m * (s - x') - 8 * y ^ 4
}

// c = a - b
func (util sm2P256Util)p256Sub(c, a, b *sm2P256FieldElement) {
	var carry uint32
	sm2util := sm2P256Util{}
	for i := 0; ; i++ {
		c[i] = a[i] - b[i]
		c[i] += sm2P256Zero31[i]
		c[i] += carry
		carry = c[i] >> 29
		c[i] &= bottom29Bits
		i++
		if i == 9 {
			break
		}
		c[i] = a[i] - b[i]
		c[i] += sm2P256Zero31[i]
		c[i] += carry
		carry = c[i] >> 28
		c[i] &= bottom28Bits
	}

	sm2util.p256ReduceCarry(c, carry)
}

// b = a
func (util sm2P256Util)p256Dup(b, a *sm2P256FieldElement) {
	*b = *a
}

// 标量运算,获取标量a
func (util sm2P256Util)p256Scalar(b *sm2P256FieldElement, a int) {

	sm2util := sm2P256Util{}
	sm2util.p256Mul(b, b, &sm2P256Factor[a])
}

func (util sm2P256Util)p256ToAffine(x, y, z *sm2P256FieldElement) (xOut, yOut *big.Int) {
	var xx, yy sm2P256FieldElement

	sm2util := sm2P256Util{}
	sm2util.p256PointToAffine(&xx, &yy, x, y, z)
	return sm2util.p256ToBig(&xx), sm2util.p256ToBig(&yy)
}

func (util sm2P256Util)p256PointToAffine(xOut, yOut, x, y, z *sm2P256FieldElement) {
	var zInv, zInvSq sm2P256FieldElement

	sm2util := sm2P256Util{}
	zz := sm2util.p256ToBig(z)
	zz.ModInverse(zz, sm2p256Params.P)
	sm2util.p256FromBig(&zInv, zz)

	sm2util.p256Square(&zInvSq, &zInv)
	sm2util.p256Mul(xOut, x, &zInvSq)
	sm2util.p256Mul(&zInv, &zInv, &zInvSq)
	sm2util.p256Mul(yOut, y, &zInv)
}

func (util sm2P256Util)p256GetScalar(b *[32]byte, a []byte) {
	var scalarBytes []byte

	n := new(big.Int).SetBytes(a)
	if n.Cmp(sm2p256Params.N) >= 0 {
		n.Mod(n, sm2p256Params.N)
		scalarBytes = n.Bytes()
	} else {
		scalarBytes = a
	}
	for i, v := range scalarBytes {
		b[len(scalarBytes)-(1+i)] = v
	}
}


func (util sm2P256Util)p256ScalarMult(xOut, yOut, zOut, x, y *sm2P256FieldElement, scalar *[32]uint8) {
	var precomp [16][3]sm2P256FieldElement
	var px, py, pz, tx, ty, tz sm2P256FieldElement
	var nIsInfinityMask, index, pIsNoninfiniteMask, mask uint32

	sm2util := sm2P256Util{}
	// We precompute 0,1,2,... times {x,y}.
	precomp[1][0] = *x
	precomp[1][1] = *y
	precomp[1][2] = sm2P256Factor[1]

	for i := 2; i < 16; i += 2 {
		sm2util.p256PointDouble(&precomp[i][0], &precomp[i][1], &precomp[i][2], &precomp[i/2][0], &precomp[i/2][1], &precomp[i/2][2])
		sm2util.p256PointAddMixed(&precomp[i+1][0], &precomp[i+1][1], &precomp[i+1][2], &precomp[i][0], &precomp[i][1], &precomp[i][2], x, y)
	}

	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}
	nIsInfinityMask = ^uint32(0)

	// We add in a window of four bits each iteration and do this 64 times.
	for i := 0; i < 64; i++ {
		if i != 0 {
			sm2util.p256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
			sm2util.p256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
			sm2util.p256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
			sm2util.p256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		}

		index = uint32(scalar[31-i/2])
		if (i & 1) == 1 {
			index &= 15
		} else {
			index >>= 4
		}

		// See the comments in scalarBaseMult about handling infinities.
		sm2util.p256SelectJacobianPoint(&px, &py, &pz, &precomp, index)
		sm2util.p256PointAdd(xOut, yOut, zOut, &px, &py, &pz, &tx, &ty, &tz)
		sm2util.p256CopyConditional(xOut, &px, nIsInfinityMask)
		sm2util.p256CopyConditional(yOut, &py, nIsInfinityMask)
		sm2util.p256CopyConditional(zOut, &pz, nIsInfinityMask)

		pIsNoninfiniteMask = nonZeroToAllOnes(index)
		mask = pIsNoninfiniteMask & ^nIsInfinityMask
		sm2util.p256CopyConditional(xOut, &tx, mask)
		sm2util.p256CopyConditional(yOut, &ty, mask)
		sm2util.p256CopyConditional(zOut, &tz, mask)
		nIsInfinityMask &^= pIsNoninfiniteMask
	}
}


func (util sm2P256Util)p256PointAddMixed(xOut, yOut, zOut, x1, y1, z1, x2, y2 *sm2P256FieldElement) {
	var z1z1, z1z1z1, s2, u2, h, i, j, r, rr, v, tmp sm2P256FieldElement

	sm2util := sm2P256Util{}
	sm2util.p256Square(&z1z1, z1)
	sm2util.p256Add(&tmp, z1, z1)

	sm2util.p256Mul(&u2, x2, &z1z1)
	sm2util.p256Mul(&z1z1z1, z1, &z1z1)
	sm2util.p256Mul(&s2, y2, &z1z1z1)
	sm2util.p256Sub(&h, &u2, x1)
	sm2util.p256Add(&i, &h, &h)
	sm2util.p256Square(&i, &i)
	sm2util.p256Mul(&j, &h, &i)
	sm2util.p256Sub(&r, &s2, y1)
	sm2util.p256Add(&r, &r, &r)
	sm2util.p256Mul(&v, x1, &i)

	sm2util.p256Mul(zOut, &tmp, &h)
	sm2util.p256Square(&rr, &r)
	sm2util.p256Sub(xOut, &rr, &j)
	sm2util.p256Sub(xOut, xOut, &v)
	sm2util.p256Sub(xOut, xOut, &v)

	sm2util.p256Sub(&tmp, &v, xOut)
	sm2util.p256Mul(yOut, &tmp, &r)
	sm2util.p256Mul(&tmp, y1, &j)
	sm2util.p256Sub(yOut, yOut, &tmp)
	sm2util.p256Sub(yOut, yOut, &tmp)
}

// p256CopyConditional sets out=in if mask = 0xffffffff in constant time.
//
// On entry: mask is either 0 or 0xffffffff.
func (util sm2P256Util)p256CopyConditional(out, in *sm2P256FieldElement, mask uint32) {
	for i := 0; i < 9; i++ {
		tmp := mask & (in[i] ^ out[i])
		out[i] ^= tmp
	}
}

// p256SelectJacobianPoint sets {out_x,out_y,out_z} to the index'th entry of
// table.
// On entry: index < 16, table[0] must be zero.
func (util sm2P256Util)p256SelectJacobianPoint(xOut, yOut, zOut *sm2P256FieldElement, table *[16][3]sm2P256FieldElement, index uint32) {
	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}

	// The implicit value at index 0 is all zero. We don't need to perform that
	// iteration of the loop because we already set out_* to zero.
	for i := uint32(1); i < 16; i++ {
		mask := i ^ index
		mask |= mask >> 2
		mask |= mask >> 1
		mask &= 1
		mask--
		for j := range xOut {
			xOut[j] |= table[i][0][j] & mask
		}
		for j := range yOut {
			yOut[j] |= table[i][1][j] & mask
		}
		for j := range zOut {
			zOut[j] |= table[i][2][j] & mask
		}
	}
}



// p256ScalarBaseMult sets {xOut,yOut,zOut} = scalar*G where scalar is a
// little-endian number. Note that the value of scalar must be less than the
// order of the group.
func (util sm2P256Util)p256ScalarBaseMult(xOut, yOut, zOut *sm2P256FieldElement, scalar *[32]uint8) {
	nIsInfinityMask := ^uint32(0)
	var px, py, tx, ty, tz sm2P256FieldElement
	var pIsNoninfiniteMask, mask, tableOffset uint32

	sm2util := sm2P256Util{}
	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}

	// The loop adds bits at positions 0, 64, 128 and 192, followed by
	// positions 32,96,160 and 224 and does this 32 times.
	for i := uint(0); i < 32; i++ {
		if i != 0 {
			sm2util.p256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		}
		tableOffset = 0
		for j := uint(0); j <= 32; j += 32 {
			bit0 := sm2util.p256GetBit(scalar, 31-i+j)
			bit1 := sm2util.p256GetBit(scalar, 95-i+j)
			bit2 := sm2util.p256GetBit(scalar, 159-i+j)
			bit3 := sm2util.p256GetBit(scalar, 223-i+j)
			index := bit0 | (bit1 << 1) | (bit2 << 2) | (bit3 << 3)

			sm2util.p256SelectAffinePoint(&px, &py, sm2P256Precomputed[tableOffset:], index)
			tableOffset += 30 * 9

			// Since scalar is less than the order of the group, we know that
			// {xOut,yOut,zOut} != {px,py,1}, unless both are zero, which we handle
			// below.
			sm2util.p256PointAddMixed(&tx, &ty, &tz, xOut, yOut, zOut, &px, &py)
			// The result of pointAddMixed is incorrect if {xOut,yOut,zOut} is zero
			// (a.k.a.  the point at infinity). We handle that situation by
			// copying the point from the table.
			sm2util.p256CopyConditional(xOut, &px, nIsInfinityMask)
			sm2util.p256CopyConditional(yOut, &py, nIsInfinityMask)
			sm2util.p256CopyConditional(zOut, &sm2P256Factor[1], nIsInfinityMask)

			// Equally, the result is also wrong if the point from the table is
			// zero, which happens when the index is zero. We handle that by
			// only copying from {tx,ty,tz} to {xOut,yOut,zOut} if index != 0.
			pIsNoninfiniteMask = nonZeroToAllOnes(index)
			mask = pIsNoninfiniteMask & ^nIsInfinityMask
			sm2util.p256CopyConditional(xOut, &tx, mask)
			sm2util.p256CopyConditional(yOut, &ty, mask)
			sm2util.p256CopyConditional(zOut, &tz, mask)
			// If p was not zero, then n is now non-zero.
			nIsInfinityMask &^= pIsNoninfiniteMask
		}
	}
}

// p256GetBit returns the bit'th bit of scalar.
func (util sm2P256Util)p256GetBit(scalar *[32]uint8, bit uint) uint32 {
	return uint32(((scalar[bit>>3]) >> (bit & 7)) & 1)
}


// p256SelectAffinePoint sets {out_x,out_y} to the index'th entry of table.
// On entry: index < 16, table[0] must be zero.
func  (util sm2P256Util)p256SelectAffinePoint(xOut, yOut *sm2P256FieldElement, table []uint32, index uint32) {
	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}

	for i := uint32(1); i < 16; i++ {
		mask := i ^ index
		mask |= mask >> 2
		mask |= mask >> 1
		mask &= 1
		mask--
		for j := range xOut {
			xOut[j] |= table[0] & mask
			table = table[1:]
		}
		for j := range yOut {
			yOut[j] |= table[0] & mask
			table = table[1:]
		}
	}
}
// ----------------------------------------------------------- //

// X = r * R mod P
// r = X * R' mod P
func (util sm2P256Util)p256ToBig(X *sm2P256FieldElement) *big.Int {
	r, tm := new(big.Int), new(big.Int)
	r.SetInt64(int64(X[8]))
	for i := 7; i >= 0; i-- {
		if (i & 1) == 0 {
			r.Lsh(r, 29)
		} else {
			r.Lsh(r, 28)
		}
		tm.SetInt64(int64(X[i]))
		r.Add(r, tm)
	}
	r.Mul(r, sm2p256Params.RInverse)
	r.Mod(r, sm2p256Params.P)
	return r
}


// X = a * R mod P  Get [9]uint32
func (util sm2P256Util)p256FromBig(X *sm2P256FieldElement, a *big.Int) {
	x := new(big.Int).Lsh(a, 257)
	x.Mod(x, sm2p256Params.P)
	for i := 0; i < 9; i++ {
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom29Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 29)
		i++
		if i == 9 {
			break
		}
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom28Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 28)
	}
}



func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}
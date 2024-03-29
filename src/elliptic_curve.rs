/*!
This crate is a minimal and easy-to-use elliptic curve library. This library
allows to perform the following operations over an elliptic curve finite cyclic
group:

- Point Addition: `R = P + Q`
- Point Doubling: `R = P + P = 2 * P`
- Scalar Multiplication: `R = d * P`

A generic elliptic curve is defined as `y^2 = x^3 + ax + b mod p`, and in this
particular library the constrains are:

 - `p` should be **a prime number** bigger than 3
 - `4 a^3 + 27 b^2 != 0`

The library could be use in any cryptographic algorithm that requires elliptic
curve groups, for example:

- Digital Signature Algorithm (DSA)
- Zero-Knowledge Proofs (ZKP)


```toml
[dependencies]
elliptic-curve-cryptography = "0.1.0"
```

## Example: `y^2 = x^3 + 2x + 2 mod 17`

```rust

use num_bigint::BigUint;


#[derive(PartialEq, Clone, Debug)]
pub enum Point {
    Coordinate(BigUint, BigUint),
    Identity,
}

let ec = EllipticCurve {
    a: BigUint::from(2u32),
    b: BigUint::from(2u32),
    p: BigUint::from(17u32),
};

// (6,3) + (5,1) = (10,6)
let p1 = Point::Coordinate(BigUint::from(6u32), BigUint::from(3u32));
let p2 = Point::Coordinate(BigUint::from(5u32), BigUint::from(1u32));
let pr = Ok(Point::Coordinate(BigUint::from(10u32), BigUint::from(6u32)));

let res = ec.add(&p1, &p2);
assert_eq!(res, pr);

let res = ec.add(&p2, &p1);
assert_eq!(res, pr);
```

## Example: `secp256k1`: `y^2 = x^3 + 7 mod p (large)`

```rust
use elliptic_curve_cryptography::{EllipticCurve, Point};
use num_bigint::BigUint;

let p = BigUint::parse_bytes(
    b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    16,
)
.expect("could not convert p");

let n = BigUint::parse_bytes(
    b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
)
.expect("could not convert n");

let gx = BigUint::parse_bytes(
    b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    16,
)
.expect("could not convert gx");

let gy = BigUint::parse_bytes(
    b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
    16,
)
.expect("could not convert gy");

let ec = EllipticCurve {
    a: BigUint::from(0u32),
    b: BigUint::from(7u32),
    p,
};

let g = Point::Coor(gx, gy);

// n * G = I (Identity)
let res = ec.scalar_mul(&g, &n);

assert_eq!(res, Ok(Point::Identity));
```

*/

use crate::GaloisField as FiniteField;
use num_bigint::BigUint;

///
/// This represents a point in the elliptic curve. The identity element is such
/// that:
///
///  - `A - A = I`
///  - `A + I = A`
///  - `I + I = 2 * I = I`
///
#[derive(PartialEq, Clone, Debug)]
pub enum FiniteFieldElement {
    Coordinate(BigUint, BigUint),
    Identity,
}

#[derive(PartialEq, Debug)]
pub enum EllipticCurveError {
    InvalidFiniteFieldElement(FiniteFieldElement),
    InvalidScalar(BigUint),
}

///
/// This represents an elliptic curve of the form
/// y^2 = x^3 + ax + b mod p
///
#[derive(PartialEq, Clone, Debug)]
pub struct EllipticCurve {
    pub a: BigUint,
    pub b: BigUint,
    pub p: BigUint,
}

impl EllipticCurve {
    ///
    /// Perform a point addition: `C = A + B` where `A` and `B` are points which
    /// belong to the curve. Geometrically speaking, the point `C` is the
    /// x-reflection of the intersection of the lines that passes through `A`
    /// and `B` and intersects the curve.
    ///
    pub fn add(
        &self,
        a: &FiniteFieldElement,
        b: &FiniteFieldElement,
    ) -> Result<FiniteFieldElement, EllipticCurveError> {
        if !self.is_on_curve(a) {
            return Err(EllipticCurveError::InvalidFiniteFieldElement(a.clone()));
        }

        if !self.is_on_curve(b) {
            return Err(EllipticCurveError::InvalidFiniteFieldElement(b.clone()));
        }

        if *a == *b {
            return self.double(a);
        }

        match (a, b) {
            (FiniteFieldElement::Identity, _) => Ok(b.clone()),
            (_, FiniteFieldElement::Identity) => Ok(a.clone()),
            (FiniteFieldElement::Coordinate(x1, y1), FiniteFieldElement::Coordinate(x2, y2)) => {
                // Check that they are not additive inverses
                let y1plusy2 = FiniteField::add(y1, y2, &self.p).unwrap();

                if x1 == x2 && y1plusy2 == BigUint::from(0u32) {
                    return Ok(FiniteFieldElement::Identity);
                }

                // s = (y2 - y1) / (x2 - x1) mod p
                let numerator = FiniteField::subtract(y2, y1, &self.p).unwrap();
                let denominator = FiniteField::subtract(x2, x1, &self.p).unwrap();
                let s = FiniteField::divide(&numerator, &denominator, &self.p).unwrap();
                // x3 = s^2 - x1 - x2 mod p
                // y3 = s(x1 - x3) - y1 mod p
                let (x3, y3) = self.compute_x3_y3(x1, y1, x2, &s);

                Ok(FiniteFieldElement::Coordinate(x3, y3))
            }
        }
    }

    ///
    /// Perform a point doubling: `B = A + A = 2 * A` where `A` is a point in
    /// the curve. Geometrically speaking, the point `B` is the intersection of
    /// the tangent line over A that intersects the curve.
    ///
    pub fn double(&self, a: &FiniteFieldElement) -> Result<FiniteFieldElement, EllipticCurveError> {
        if !self.is_on_curve(a) {
            return Err(EllipticCurveError::InvalidFiniteFieldElement(a.clone()));
        }

        match a {
            FiniteFieldElement::Identity => Ok(FiniteFieldElement::Identity),
            FiniteFieldElement::Coordinate(x1, y1) => {
                if *y1 == BigUint::from(0u32) {
                    return Ok(FiniteFieldElement::Identity);
                }

                // s = (3 * x1^2 + a) / (2 * y1) mod p
                let numerator = x1.modpow(&BigUint::from(2u32), &self.p);
                let numerator =
                    FiniteField::mult(&BigUint::from(3u32), &numerator, &self.p).unwrap();
                let numerator = FiniteField::add(&self.a, &numerator, &self.p).unwrap();

                let denominator = FiniteField::mult(&BigUint::from(2u32), y1, &self.p).unwrap();
                let s = FiniteField::divide(&numerator, &denominator, &self.p).unwrap();

                let (x3, y3) = self.compute_x3_y3(x1, y1, x1, &s);

                Ok(FiniteFieldElement::Coordinate(x3, y3))
            }
        }
    }

    ///
    /// computes the resulting point of the addition:
    ///  `C(x3,y3) = A(x1,y1) + B(x2,y2)`:
    ///
    /// `s` is given as input and should be computed differently depending on it
    /// is point doubling or point addition:
    ///
    /// - `B != A => s = (y2 - y1) / (x2 - x1) mod p`
    /// - `B == A => s = (3 * x1^2 + a) / (2 * y1) mod p`
    ///
    /// Result:
    ///
    /// - `x3 = s^2 - x1 - x2 mod p`
    /// - `y3 = s(x1 - x3) - y1 mod p`
    ///
    fn compute_x3_y3(
        &self,
        x1: &BigUint,
        y1: &BigUint,
        x2: &BigUint,
        s: &BigUint,
    ) -> (BigUint, BigUint) {
        let s2 = s.modpow(&BigUint::from(2u32), &self.p);
        let x3 = FiniteField::subtract(&s2, x1, &self.p).unwrap();
        let x3 = FiniteField::subtract(&x3, x2, &self.p).unwrap();

        let y3 = FiniteField::subtract(x1, &x3, &self.p).unwrap();
        let y3 = FiniteField::mult(s, &y3, &self.p).unwrap();
        let y3 = FiniteField::subtract(&y3, y1, &self.p).unwrap();

        (x3, y3)
    }

    ///
    /// Perform a scalar multiplication of a point: `B = d * A` where `A` is a
    /// point in the curve and `d > 0` is a positive scalar of any value.
    ///
    /// It uses the addition/doubling algorithm
    ///
    /// ```text
    ///  T = A
    ///  for i in [(bits of d)-1), 0]
    ///       T = 2 * T
    ///       if bit i of d == 1
    ///           T = T + A
    /// ```
    ///
    pub fn scalar_mul(
        &self,
        a: &FiniteFieldElement,
        d: &BigUint,
    ) -> Result<FiniteFieldElement, EllipticCurveError> {
        if *d == BigUint::from(0u32) {
            return Err(EllipticCurveError::InvalidScalar(d.clone()));
        }

        let mut t = a.clone();
        for i in (0..(d.bits() - 1)).rev() {
            t = self.double(&t)?;
            if d.bit(i) {
                t = self.add(&t, a)?;
            }
        }
        Ok(t)
    }

    ///
    /// Checks if a point A = (x,y) belongs to the elliptic curve:
    ///
    /// if `y^2 = x^3 + a * x + b mod p` then returns `true`, if not, returns
    /// `false`.
    ///
    pub fn is_on_curve(&self, a: &FiniteFieldElement) -> bool {
        match a {
            FiniteFieldElement::Coordinate(x, y) => {
                let y2 = y.modpow(&BigUint::from(2u32), &self.p);
                let x3 = x.modpow(&BigUint::from(3u32), &self.p);
                let ax = FiniteField::mult(&self.a, x, &self.p).unwrap();
                let x3plusax = FiniteField::add(&x3, &ax, &self.p).unwrap();

                y2 == FiniteField::add(&x3plusax, &self.b, &self.p).unwrap()
            }
            FiniteFieldElement::Identity => true,
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_point_in_curve() {
        // y^2 = x^3 + 2x + 2 mod 17
        let ec = EllipticCurve {
            a: BigUint::from(2u32),
            b: BigUint::from(2u32),
            p: BigUint::from(17u32),
        };

        // (6,3) + (5,1) = (10,6)
        let p1 = FiniteFieldElement::Coordinate(BigUint::from(6u32), BigUint::from(3u32));
        let p2 = FiniteFieldElement::Coordinate(BigUint::from(5u32), BigUint::from(1u32));
        let p3 = FiniteFieldElement::Coordinate(BigUint::from(10u32), BigUint::from(6u32));

        assert!(ec.is_on_curve(&p1));
        assert!(ec.is_on_curve(&p2));
        assert!(ec.is_on_curve(&p3));

        let p4 = FiniteFieldElement::Coordinate(BigUint::from(4u32), BigUint::from(1u32));
        let p5 = FiniteFieldElement::Coordinate(BigUint::from(1u32), BigUint::from(1u32));
        let p6 = FiniteFieldElement::Coordinate(BigUint::from(0u32), BigUint::from(1u32));

        assert!(!ec.is_on_curve(&p4));
        assert!(!ec.is_on_curve(&p5));
        assert!(!ec.is_on_curve(&p6));
    }

    #[test]
    fn test_point_addition() {
        // y^2 = x^3 + 2x + 2 mod 17
        let ec = EllipticCurve {
            a: BigUint::from(2u32),
            b: BigUint::from(2u32),
            p: BigUint::from(17u32),
        };

        // (6,3) + (5,1) = (10,6)
        let p1 = FiniteFieldElement::Coordinate(BigUint::from(6u32), BigUint::from(3u32));
        let p2 = FiniteFieldElement::Coordinate(BigUint::from(5u32), BigUint::from(1u32));
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(10u32),
            BigUint::from(6u32),
        ));

        let res = ec.add(&p1, &p2);
        assert_eq!(res, pr);

        let res = ec.add(&p2, &p1);
        assert_eq!(res, pr);

        // (5,1) + (5,1) = (6,3)
        let p1 = FiniteFieldElement::Coordinate(BigUint::from(5u32), BigUint::from(1u32));
        let p2 = FiniteFieldElement::Coordinate(BigUint::from(5u32), BigUint::from(1u32));
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(6u32),
            BigUint::from(3u32),
        ));

        let res = ec.add(&p1, &p2);
        assert_eq!(res, pr);

        // (10, 6) + (5, 1) = (3,1)
        let p1 = FiniteFieldElement::Coordinate(BigUint::from(10u32), BigUint::from(6u32));
        let p2 = FiniteFieldElement::Coordinate(BigUint::from(5u32), BigUint::from(1u32));
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(3u32),
            BigUint::from(1u32),
        ));

        let res = ec.add(&p1, &p2);
        assert_eq!(res, pr);

        // (16, 13) + (5, 1) = (0, 6)
        let p1 = FiniteFieldElement::Coordinate(BigUint::from(16u32), BigUint::from(13u32));
        let p2 = FiniteFieldElement::Coordinate(BigUint::from(5u32), BigUint::from(1u32));
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(0u32),
            BigUint::from(6u32),
        ));

        let res = ec.add(&p1, &p2);
        assert_eq!(res, pr);

        // (6,3) + I = (6,3)
        let p1 = FiniteFieldElement::Coordinate(BigUint::from(6u32), BigUint::from(3u32));

        let res = ec.add(&p1, &FiniteFieldElement::Identity);
        assert_eq!(res, Ok(p1.clone()));

        let res = ec.add(&FiniteFieldElement::Identity, &p1);
        assert_eq!(res, Ok(p1.clone()));

        // I + I = 2 * I = I
        let res = ec.add(&FiniteFieldElement::Identity, &FiniteFieldElement::Identity);
        assert_eq!(res, Ok(FiniteFieldElement::Identity));

        // (5,16) + (5,1) = I
        let p1 = FiniteFieldElement::Coordinate(BigUint::from(5u32), BigUint::from(16u32));
        let p2 = FiniteFieldElement::Coordinate(BigUint::from(5u32), BigUint::from(1u32));

        let res = ec.add(&p1, &p2);
        assert_eq!(res, Ok(FiniteFieldElement::Identity));

        let res = ec.add(&p2, &p1);
        assert_eq!(res, Ok(FiniteFieldElement::Identity));
    }

    #[test]
    fn test_point_doubling() {
        // y^2 = x^3 + 2x + 2 mod 17
        let ec = EllipticCurve {
            a: BigUint::from(2u32),
            b: BigUint::from(2u32),
            p: BigUint::from(17u32),
        };

        // (5,1) + (5,1) = 2 (5, 1) = (6,3)
        let p1 = FiniteFieldElement::Coordinate(BigUint::from(5u32), BigUint::from(1u32));
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(6u32),
            BigUint::from(3u32),
        ));

        let res = ec.double(&p1);
        assert_eq!(res, pr);

        // I + I = 2 * I = I
        let res = ec.double(&FiniteFieldElement::Identity);
        assert_eq!(res, Ok(FiniteFieldElement::Identity));
    }

    #[test]
    fn test_scalar_multiplication() {
        // y^2 = x^3 + 2x + 2 mod 17   |G| = 19  19 * A = I
        let ec = EllipticCurve {
            a: BigUint::from(2u32),
            b: BigUint::from(2u32),
            p: BigUint::from(17u32),
        };

        let a = FiniteFieldElement::Coordinate(BigUint::from(5u32), BigUint::from(1u32));

        // 2 * (5, 1) = (6,3)
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(6u32),
            BigUint::from(3u32),
        ));
        let res = ec.scalar_mul(&a, &BigUint::from(2u32));
        assert_eq!(res, pr);

        // 10 * (5, 1) = (7,11)
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(7u32),
            BigUint::from(11u32),
        ));
        let res = ec.scalar_mul(&a, &BigUint::from(10u32));
        assert_eq!(res, pr);

        // 15 * (5, 1) = (3,16)
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(3u32),
            BigUint::from(16u32),
        ));
        let res = ec.scalar_mul(&a, &BigUint::from(15u32));
        assert_eq!(res, pr);

        // 16 * (5, 1) = (10,11)
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(10u32),
            BigUint::from(11u32),
        ));
        let res = ec.scalar_mul(&a, &BigUint::from(16u32));
        assert_eq!(res, pr);

        // 17 * (5, 1) = (6,14)
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(6u32),
            BigUint::from(14u32),
        ));
        let res = ec.scalar_mul(&a, &BigUint::from(17u32));
        assert_eq!(res, pr);

        // 18 * (5, 1) = (5,16)
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(5u32),
            BigUint::from(16u32),
        ));
        let res = ec.scalar_mul(&a, &BigUint::from(18u32));
        assert_eq!(res, pr);

        // 19 * (5, 1) = I
        let pr = Ok(FiniteFieldElement::Identity);
        let res = ec.scalar_mul(&a, &BigUint::from(19u32));
        assert_eq!(res, pr);

        // 2 * (10, 6) = (16,13)
        let p1 = FiniteFieldElement::Coordinate(BigUint::from(10u32), BigUint::from(6u32));
        let pr = Ok(FiniteFieldElement::Coordinate(
            BigUint::from(16u32),
            BigUint::from(13u32),
        ));

        let res = ec.double(&p1);
        assert_eq!(res, pr);
    }

    #[test]
    fn test_ec_secp256k1() {
        /*
          y^2 = x^3 + 7 mod p (large)

          p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
          n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        G = (
            x = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798,
            y = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
        )
        a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
        b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007
        */

        // n * G = I
        let p = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16,
        )
        .expect("could not convert p");

        let n = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .expect("could not convert n");

        let gx = BigUint::parse_bytes(
            b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            16,
        )
        .expect("could not convert gx");

        let gy = BigUint::parse_bytes(
            b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            16,
        )
        .expect("could not convert gy");

        let ec = EllipticCurve {
            a: BigUint::from(0u32),
            b: BigUint::from(7u32),
            p,
        };

        let g = FiniteFieldElement::Coordinate(gx, gy);

        let res = ec.scalar_mul(&g, &n); // n * G
        assert_eq!(res, Ok(FiniteFieldElement::Identity));

        // p = 1201 * G -> it is also a generator
        let p = ec.scalar_mul(&g, &BigUint::from(1201u32)).unwrap();

        let res = ec.scalar_mul(&p, &n); // n * p
        assert_eq!(res, Ok(FiniteFieldElement::Identity));
    }
}

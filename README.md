# Wrapper of openssl library

# Usage
First, install openssl library, read more [here](https://docs.rs/openssl/latest/openssl/).

Second, add wrapper to your project
```
cargo add --git https://github.com/LaGipeR/wrapper
```

#### Some examples

Create a group of point over elliptic curve of prime field, where components a, b, p make up the formula <br> 
__y^2 mod p = x^3 + ax + b mod p.__

<br>

```Rust
// components of a group
let a = LongInt::from_hex("0");
let b = LongInt::from_hex("7");
let p = LongInt::from_hex("11"); // 17 in decimal

let group = Group::new(&a, &b, &p); // group with components a = 0, b = 7, p = 17
```

Create a point in group

```Rust
// point cords
let x = LongInt::from_hex("1");
let y = LongInt::from_hex("5");

let point = Point::with_cords(&group, &x, &y); // point with cords (1, 5)
```

or 

```Rust
let point = Point::inf(&group); // infinity point
```

Add two points, that are in the same group

```Rust
let p3 = &p1 + &p2; // the sum of two points
```

Multiply scalar by point

```Rust
let scalar = LongInt::from_hex("9"); // any number;
let sp = &scalar * &point; // product of scalar by point
```

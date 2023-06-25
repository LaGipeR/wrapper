use long_int::LongInt;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcGroupRef, EcPoint, EcPointRef, PointConversionForm};
use std::ops::{Add, Mul};

const FORM: PointConversionForm = PointConversionForm::UNCOMPRESSED;

pub struct Group(EcGroup);

impl Clone for Group {
    fn clone(&self) -> Self {
        let (a, b, p) = self.get_components();

        Group::new(&a, &b, &p)
    }
}

impl PartialEq for Group {
    fn eq(&self, other: &Self) -> bool {
        let (sa, sb, sp) = self.get_components();
        let (oa, ob, op) = other.get_components();

        (sp == op) && (sa == oa) && (sb == ob)
    }
}

impl From<&EcGroupRef> for Group {
    fn from(value: &EcGroupRef) -> Self {
        let (a, b, p) = get_components(&value);
        Group::new(&a, &b, &p)
    }
}

impl Group {
    pub fn new(a: &LongInt, b: &LongInt, p: &LongInt) -> Group {
        let mut ctx = BigNumContext::new().unwrap();

        let a = BigNum::from_hex_str(&a.getHex()).unwrap();
        let b = BigNum::from_hex_str(&b.getHex()).unwrap();
        let p = BigNum::from_hex_str(&p.getHex()).unwrap();

        Group(EcGroup::from_components(p, a, b, &mut ctx).unwrap())
    }

    pub fn get_generator(&self) -> Point {
        let (x, y) = get_cords(self.0.generator(), &self.0);
        Point::with_cords(self, &x, &y)
    }

    fn get_components(&self) -> (LongInt, LongInt, LongInt) {
        get_components(self.0.as_ref())
    }
}

pub struct Point {
    point: EcPoint,
    group: Group,
}

impl Clone for Point {
    fn clone(&self) -> Self {
        let (x, y) = self.get_cords();

        Point::with_cords(&self.group.clone(), &x, &y)
    }
}

impl ToString for Point {
    fn to_string(&self) -> String {
        let mut ctx = BigNumContext::new().unwrap();
        let bytes = self.point.to_bytes(&self.group.0, FORM, &mut ctx).unwrap();

        hex::encode(bytes)
    }
}

impl Point {
    pub fn with_cords(group: &Group, x: &LongInt, y: &LongInt) -> Point {
        let mut ctx = BigNumContext::new().unwrap();

        let mut point = EcPoint::new(&group.0).unwrap();

        let x = BigNum::from_hex_str(&x.getHex()).unwrap();
        let y = BigNum::from_hex_str(&y.getHex()).unwrap();
        point
            .set_affine_coordinates_gfp(&group.0, &x, &y, &mut ctx)
            .unwrap();

        Point{
            point,
            group: (*group).clone()
        }
    }

    pub fn inf(group: &Group) -> Point {
        Point {
            point: EcPoint::new(&group.0).unwrap(),
            group: (*group).clone(),
        }
    }

    pub fn from_string(group: &Group, string: &str) -> Point {
        let mut ctx = BigNumContext::new().unwrap();
        Point {
            point: EcPoint::from_bytes(&group.0, &hex::decode(string).unwrap(), &mut ctx).unwrap(),
            group: (*group).clone(),
        }
    }

    pub fn get_cords(&self) -> (LongInt, LongInt) {
        get_cords(self.point.as_ref(), &self.group.0)
    }

    pub fn is_on_curve(&self) -> bool {
        let mut ctx = BigNumContext::new().unwrap();

        self.point.is_on_curve(&self.group.0, &mut ctx).unwrap()
    }
}

impl Add<&Point> for &Point {
    type Output = Point;

    fn add(self, rhs: &Point) -> Self::Output {
        if !(self.group == rhs.group) {
            panic!("try to add points with different group");
        }

        let mut ctx = BigNumContext::new().unwrap();

        let mut res = EcPoint::new(&self.group.0).unwrap();
        res.add(&self.group.0, &self.point, &rhs.point, &mut ctx).unwrap();

        Point {
            point: res,
            group: self.group.clone(),
        }
    }
}
impl Add<&Point> for Point {
    type Output = Point;

    fn add(self, rhs: &Point) -> Self::Output {
        &self + rhs
    }
}
impl Add<Point> for &Point {
    type Output = Point;

    fn add(self, rhs: Point) -> Self::Output {
        self + &rhs
    }
}
impl Add<Point> for Point {
    type Output = Point;

    fn add(self, rhs: Point) -> Self::Output {
        &self + &rhs
    }
}

impl Mul<&LongInt> for &Point {
    type Output = Point;

    fn mul(self, rhs: &LongInt) -> Self::Output {
        let mut ctx = BigNumContext::new().unwrap();

        let mut res = EcPoint::new(&self.group.0).unwrap();

        res.mul(&self.group.0, &self.point, &long_int2big_num(rhs), &mut ctx).unwrap();

        ec_point2point(&res, &self.group.0)
    }
}
impl Mul<&LongInt> for Point {
    type Output = Point;

    fn mul(self, rhs: &LongInt) -> Self::Output {
        &self * rhs
    }
}
impl Mul<LongInt> for &Point {
    type Output = Point;

    fn mul(self, rhs: LongInt) -> Self::Output {
        self * &rhs
    }
}
impl Mul<LongInt> for Point {
    type Output = Point;

    fn mul(self, rhs: LongInt) -> Self::Output {
        &self * &rhs
    }
}

fn big_num2long_int(big_num: &BigNum) -> LongInt {
    LongInt::from_hex(&big_num.to_hex_str().unwrap().to_lowercase())
}

fn long_int2big_num(long_int_: &LongInt) -> BigNum {
    BigNum::from_hex_str(&long_int_.getHex()).unwrap()
}

fn get_components(group: &EcGroupRef) -> (LongInt, LongInt, LongInt) {
    let mut ctx = BigNumContext::new().unwrap();

    let mut p = BigNum::new().unwrap();
    let mut a = BigNum::new().unwrap();
    let mut b = BigNum::new().unwrap();
    group.components_gfp(&mut p, &mut a, &mut b, &mut ctx).unwrap();

    (big_num2long_int(&a), big_num2long_int(&b), big_num2long_int(&p))
}

fn get_cords(point: &EcPointRef, group: &EcGroup) -> (LongInt, LongInt) {
    let mut ctx = BigNumContext::new().unwrap();

    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();

    point
        .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
        .unwrap();

    (big_num2long_int(&x), big_num2long_int(&y))
}

fn ec_point2point(ec_point: &EcPoint, group: &EcGroup) -> Point {
    let (x, y) = get_cords(ec_point, group);
    Point::with_cords(&Group::from(group.as_ref()), &x, &y)
}
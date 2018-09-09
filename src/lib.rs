extern crate rand;
extern crate sha3;
extern crate digest;
extern crate byteorder;
extern crate pairing;

mod common;

use rand::{ Rng, Rand };
use pairing::{ Engine, Field, CurveProjective, CurveAffine, PrimeField };
use pairing::bls12_381::{ Bls12, Fr, G1, G2, Fq12 };
use common::str_to_fr;


pub type Gt = Fq12;

pub struct Msk(Fr, Fr);
pub struct Mpk {
    g: (G1, G2),
    xx: G1,
    yy: G1
}
pub struct Sk(Fr, G2);
pub struct Hdr {
    aa: G1,
    bb: G1,
    cc: G1
}


pub fn setup<R: Rng>(rng: &mut R) -> (Msk, Mpk) {
    // g <- G
    let g = (G1::rand(rng), G2::rand(rng));

    let g_affine = (g.0.into_affine(), g.1.into_affine());

    // x <- ZZ
    // y <- ZZ
    let x = Fr::rand(rng);
    let y = Fr::rand(rng);

    // X = g^x
    // Y = g^y
    let xx = g_affine.0.mul(x.into_repr());
    let yy = g_affine.0.mul(y.into_repr());

    (Msk(x, y), Mpk { g, xx, yy })
}

pub fn keygen<R: Rng>(rng: &mut R, mpk: &Mpk, msk: &Msk, id: &str) -> Sk {
    let Mpk { g, .. } = mpk;
    let Msk(x, y) = msk;

    // r <- ZZ
    let r = Fr::rand(rng);

    // t = (r + id) * y + x
    let mut t = str_to_fr(id);
    t.add_assign(&r);
    t.mul_assign(&y);
    t.add_assign(&x);

    if let Some(e) = t.inverse() {
        // R = g^(1/t)
        let rr = g.1.into_affine().mul(e.into_repr());
        Sk(r, rr)
    } else {
        keygen(rng, mpk, msk, id)
    }
}


pub fn enc<R: Rng>(rng: &mut R, mpk: &Mpk, ids: &[&str]) -> (Gt, Hdr) {
    let Mpk { g, xx, yy } = mpk;

    // s <- ZZ
    let s = Fr::rand(rng);

    // a = prod_(j=1)^n ID_j * s
    let a = ids.iter()
        .map(|id| {
            let mut id = str_to_fr(id);
            id.mul_assign(&s);
            id
        })
        .fold(Fr::one(), |mut sum, next| {
            sum.mul_assign(&next);
            sum
        });

    // A = Y^a
    let aa = yy.into_affine().mul(a.into_repr());

    // B = X^s
    let bb = xx.into_affine().mul(s.into_repr());

    // C = Y^s
    let cc = yy.into_affine().mul(s.into_repr());

    // k = e(g, g)^s
    let k = Bls12::pairing(g.0, g.1.into_affine().mul(s.into_repr()));

    (k, Hdr { aa, bb ,cc })
}

pub fn dec(sk: &Sk, ct: &Hdr, id: &str, ids: &[&str]) -> Option<Gt> {
    let Sk(r, rr) = sk;
    let Hdr { aa, bb ,cc } = ct;

    // a = prod_(j=1,j!=i)^n ID_j
    let a = ids.iter()
        .filter(|&vid| vid != &id)
        .fold(Fr::one(), |mut sum, next| {
            let id = str_to_fr(next);
            sum.mul_assign(&id);
            sum
        });

    // T = A^(1/a) * B * C^r
    let mut t = aa.into_affine().mul(a.inverse()?.into_repr());
    t.add_assign(&bb);
    t.add_assign(&cc.into_affine().mul(r.into_repr()));

    // e(T, R)
    Some(Bls12::pairing(t, rr.into_affine()))
}


#[test]
fn test_ibbe() {
    use rand::thread_rng;

    let mut rng = thread_rng();

    let (msk, mpk) = setup(&mut rng);
    let sk = keygen(&mut rng, &mpk, &msk, "alice@ibe.rs");
    let (k, ct) = enc(&mut rng, &mpk, &["alice@ibe.rs", "bob@ibe.rs"]);
    let k2 = dec(&sk, &ct, "alice@ibe.rs", &["alice@ibe.rs", "bob@ibe.rs"]).unwrap();
    assert_eq!(k, k2);
}

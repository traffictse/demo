use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;

// for check_sig
use curv::arithmetic::Converter;
use sha2::Digest;

// for check_sig_secp256k1
use secp256k1::{Message, PublicKey as OtherPublicKey, Signature as OtherSignature, SECP256K1};

// for verify
use curv::arithmetic::Integer;

fn main() {
    // test vectors for check_sig
    let mut sk = Scalar::<Secp256k1>::random();
    while sk.is_zero() {
        sk = Scalar::<Secp256k1>::random(); 
    }
    let pk = Point::<Secp256k1>::generator() * &sk;
    let msg = BigInt::from(123456u32);
    let hashed_msg = BigInt::from_bytes(&sha2::Sha256::digest(&BigInt::to_bytes(&msg)));
    let mut nonce = Scalar::<Secp256k1>::random();
    while nonce.is_zero() {
        nonce = Scalar::<Secp256k1>::random(); 
    }
    let r_point = Point::<Secp256k1>::generator() * &nonce;
    let r: Scalar<Secp256k1> = Scalar::<Secp256k1>::from_bigint(&r_point.x_coord().unwrap());
    let k_inv: Scalar<Secp256k1> = nonce.invert().unwrap();
    let s = &k_inv * (Scalar::<Secp256k1>::from_bigint(&hashed_msg) + &sk * &r);
    if r.is_zero() || s.is_zero() {
        panic!("either zero r or zero s!");
    }
    check_sig(&r, &s, &hashed_msg, &pk);
    println!("check sig!");
    verify(&r, &s, &hashed_msg, &pk);
    println!("ZenGo's verify in party_i.rs!");
    check_sig_secp256k1(&r, &s, &hashed_msg, &pk);
    println!("ZenGo's check_sig in examples/common.rs!"); 
}

// from ZenGo-X multi-party-ecdsa party_i.rs
pub fn verify(r: &Scalar<Secp256k1>, s: &Scalar<Secp256k1>, message: &BigInt, y: &Point<Secp256k1>) {
    let b = s.invert().unwrap();
    let a = Scalar::<Secp256k1>::from(message);
    let u1 = a * &b;
    let u2 = r * &b;

    let g = Point::generator();
    let gu1 = g * u1;
    let yu2 = y * &u2;
    // can be faster using shamir trick

    assert_eq!(*r, Scalar::<Secp256k1>::from(
            &(gu1 + yu2)
                .x_coord()
                .unwrap()
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        ));
}

// msg = hashed message
pub fn check_sig(
    r: &Scalar<Secp256k1>,
    s: &Scalar<Secp256k1>,
    msg: &BigInt,
    pk: &Point<Secp256k1>,
) {
    // input parameter msg is a hashed value of the raw message to be signed
    let s_inv: Scalar<Secp256k1> = s.invert().unwrap_or_else(|| Scalar::<Secp256k1>::zero());
    let r_prime =
        (&s_inv * &Scalar::<Secp256k1>::from_bigint(&msg)) * Point::generator() + (r * &s_inv) * pk;
    assert_eq!(
        //r_prime.x_coord().unwrap_or_else(|| BigInt::from(0u16)),
        Scalar::from_bigint(&r_prime.x_coord().unwrap_or_else(|| BigInt::from(0u16))),
        //r.to_bigint()
        *r,
    );
}

// check_sig using secp256k1 crate
// msg = hashed message
pub fn check_sig_secp256k1(
    r: &Scalar<Secp256k1>,
    s: &Scalar<Secp256k1>,
    msg: &BigInt,
    pk: &Point<Secp256k1>,
) {
    // input parameter msg is a hashed value of the raw message to be signed
    let raw_msg = BigInt::to_bytes(msg);
    let mut msg: Vec<u8> = Vec::new(); /* padding */
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::from_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.to_bytes(false).to_vec();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = OtherPublicKey::from_slice(&raw_pk).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = OtherSignature::from_compact(compact.as_slice()).unwrap();

    let is_correct = SECP256K1.verify(&msg, &secp_sig, &pk).is_ok();
    assert!(is_correct);
}

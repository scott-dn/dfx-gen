use ic_types::Principal;
use pem::{encode, Pem};
use ring::signature::KeyPair;
use ring::{rand, signature};
use simple_asn1::{
    oid, to_der,
    ASN1Block::{BitString, ObjectIdentifier, Sequence},
};
use std::fs;
use std::iter;
use std::thread;

fn main() {
    let threads: Vec<_> = iter::repeat_with(|| {
        thread::spawn(move || loop {
            let rng = rand::SystemRandom::new();
            let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

            let pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

            let p = Principal::self_authenticating(der_encode_public_key(
                pair.public_key().as_ref().to_vec(),
            ))
            .to_text();
            if p.starts_with("scott") {
                println!("principal: {}", p);
                let encoded_pem = encode(&Pem {
                    tag: "PRIVATE KEY".into(),
                    contents: pkcs8.as_ref().to_vec(),
                });
                fs::write(p.clone(), encoded_pem).expect("Write to pem failed");

                let metadata = fs::metadata(p.clone()).expect("Read metadata failed");
                let mut permissions = metadata.permissions();
                permissions.set_readonly(true);

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    permissions.set_mode(0o400);
                }

                fs::set_permissions(p, permissions).expect("Set permission failed");
                println!("Generate identity successfully");
            }
        })
    })
    .take(4)
    .collect();
    for thread in threads {
        thread.join().unwrap()
    }
}

fn der_encode_public_key(public_key: Vec<u8>) -> Vec<u8> {
    let id_ed25519 = oid!(1, 3, 101, 112);
    let algorithm = Sequence(0, vec![ObjectIdentifier(0, id_ed25519)]);
    let subject_public_key = BitString(0, public_key.len() * 8, public_key);
    let subject_public_key_info = Sequence(0, vec![algorithm, subject_public_key]);
    to_der(&subject_public_key_info).expect("DER encoding failed")
}

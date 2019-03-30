#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate bitcrypto as crypto;

fuzz_target!(|data: &[u8]| {
    crypto::ripemd160(data);
    crypto::sha1(data);
    crypto::sha256(data);
    crypto::dhash160(data);
    crypto::dhash256(data);
    crypto::checksum(data);
});

#[macro_use]
extern crate afl;
extern crate bitcrypto as crypto;

fn main() {
	fuzz!(|data: &[u8]| {
		crypto::ripemd160(data);
		crypto::sha1(data);
		crypto::sha256(data);
		crypto::dhash160(data);
		crypto::dhash256(data);
		crypto::checksum(data);
	});
}

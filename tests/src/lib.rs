#[cfg(test)]
mod ffi;
#[cfg(test)]
#[cfg(test)]
mod helpers;

#[cfg(test)]
mod aes;
#[cfg(test)]
mod bigint;
#[cfg(test)]
mod chacha_poly_aead;
#[cfg(test)]
mod gcm;
#[cfg(test)]
mod hashes;
#[cfg(test)]
mod hmac_hkdf;
#[cfg(test)]
mod registry;
#[cfg(test)]
mod x25519;

#[cfg(test)]
mod missing {
    include!(concat!(env!("OUT_DIR"), "/missing_symbols.rs"));
}

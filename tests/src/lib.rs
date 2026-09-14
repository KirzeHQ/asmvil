#![allow(dead_code)]

#[cfg(target_arch = "x86_64")]
mod ffi;
#[cfg(target_arch = "x86_64")]
mod fixture;
#[cfg(target_arch = "x86_64")]
mod helpers;

#[cfg(all(test, target_arch = "x86_64"))]
mod aes;
#[cfg(all(test, target_arch = "x86_64"))]
mod bigint;
#[cfg(all(test, target_arch = "x86_64"))]
mod chacha_poly_aead;
#[cfg(all(test, target_arch = "x86_64"))]
mod gcm;
#[cfg(all(test, target_arch = "x86_64"))]
mod hashes;
#[cfg(all(test, target_arch = "x86_64"))]
mod hmac_hkdf;
#[cfg(all(test, target_arch = "x86_64"))]
mod x25519;

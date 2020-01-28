# Toy-RSA Library

##### Logan Ballard
##### CS510 -- Winter 2020 -- 01/28/2020

A toy and without a doubt not cryptographically secure implmentation of the RSA encryption algorithm for CS510 - Rust. 
It exposes several public functions which can be used for encryption and decryption as outlined in the RSA protocol. The
functions are defined in `src/lib.rs`.  There are comprehensive tests which test individual functions as well as the 
encryption and successful decryption of messages (unsigned 32-bit integers). 

### Implementation and Testing

I originally created the stubbed out functions that were given in the assignment documentation:

```rust
pub const EXP: u64 = 65_537;
pub fn genkey() -> (u32, u32)
pub fn encrypt(key: u64, msg: u32) -> u64
pub fn decrypt(key: (u32, u32), msg: u64) -> u32
```

From here, I was able to create several tests that validated behavior of these particular functions.  I went from the 
easiest to implement (encrypt) to the hardest (encrypt).  From there, I went through each and implemented until the tests
were passing.  From there, I wrote an end-to-end test that would randomize values for the "message", then encrypt and decrypt
the message and validate that the decrypted message was the same as the original message.

### How it Went

This went pretty well.  Being able to use provided library functions allowed me to implement and prototype the various 
areas of functionality quickly.  I got tripped up on the order of the parameters for the provided `modinverse` function,
but was able to resolve that problem somewhat quickly.  The other area that gave me a bit of trouble was the actual structuring 
of the package (`./src` and `./test`) and using `cargo` to accurately build and test.  After reviewing some notes as well 
as some of rust's top-notch documentation, I was able to resolve those issues.
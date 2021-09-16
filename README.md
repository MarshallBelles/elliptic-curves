# RustCrypto: Elliptic Curves #Flow-Rust-SDK Version

This is a heavily modified version of [elliptic-curves](https://github.com/RustCrypto/elliptic-curves) for use with the [Flow-Rust-SDK](https://github.com/MarshallBelles/flow-rust-sdk).

## Security Warning Contained Within Package Dependencies:

⚠️ Security Warning
The elliptic curve arithmetic contained in this crate has never been independently audited!

This crate has been designed with the goal of ensuring that secret-dependent operations are performed in constant time (using the subtle crate and constant-time formulas). However, it has not been thoroughly assessed to ensure that generated assembly is constant time on common CPU architectures.

USE AT YOUR OWN RISK!


## License

This project is licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

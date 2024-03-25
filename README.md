# idntkown

Identity key ownership.

The software is meant to be used primarily for storing, signing and sharing
keys generated via public-secret key cryptography. Example use case is something
similar to Web of Trust. This software also covers some GPG functionality by
using modern crypto library.

## Overview

There are 3 groups of sub-commands, each working with a corresponding file:

-   Secret key: `IDNTKOWN_SECFILE`. The file stores secret and
    public key, and log entries of signing and revocation of public keys.
-   Signed key: `IDNTKOWN_SIGFILE`. The file stores signed public
    keys and can be thought of a "database" of all known signed public keys.
-   Public key: `IDNTKOWN_PUBFILE`. The file stores known public
    keys and is used to verify signatures and encrypt messages to multiple
    recipients. This file can be though of a "contacts" database.

Key pair has an optional URL field that is meant to point to contact information
or any other information that could be useful, for example key revocation and
signature log. The exact structure of paths behind that URL is yet to be
defined.

## Shortcomings

The errors returned may be quite unclear, be sure to verify the inputs to the
command line arguments.

Some features such as clear signing, base64 encoding of blobs, URL structure
and verification, and smart-card inter-op are not implemented.

## License

Licensed under the [MIT license](LICENSE).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, shall be licensed under the MIT license,
without any additional terms or conditions.

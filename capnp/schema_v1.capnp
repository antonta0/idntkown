@0x891aa7e5b7097eae;

# Blake2b 32-byte checksum.
struct KeyId {
  bytes1 @0 :UInt64;
  bytes2 @1 :UInt64;
  bytes3 @2 :UInt64;
  bytes4 @3 :UInt64;
}

# Header used for secret and public keys.
struct Header {
  # KeyID of the unencrypted secret key.
  keyId    @0 :KeyId;
  # Meta encodes key algorithm and a version of the b[inary used to generate a key.
  meta     @1 :UInt64;
  # A timestamp when the key was generated at.
  utcstamp @2 :Int64;
}

# An encrypted secret key.
struct SecretKey {
  header   @0 :Header;
  # A label to refer to that key. Can be anything - given name, first and last
  # name, username, etc.
  label    @1 :Text;
  key      @2 :EncryptedData;
  # URL is optional and can be used to check for signature and revocation logs,
  # as well as contact information.
  url      @3 :Text;
}

# Symmetrically encrypted data with a key derived from a password.
# Used for sealing the secret key.
struct EncryptedData {
  data  @0 :Data;
  state @1 :XChaCha20Poly1305Scrypt;

  struct XChaCha20Poly1305Scrypt {
    # Salt shared between PBKDF and symmetric encryption.
    salt @0 :Data;
    tag  @1 :Data;
  }
}

# A public key.
struct PublicKey {
  header   @0 :Header;
  # A label to refer to that key. Can be anything - given name, first and last
  # name, username, etc.
  label    @1 :Text;
  key      @2 :Data;
  # URL is optional and can be used to check for signature and revocation logs,
  # as well as contact information.
  url      @3 :Text;
}

# A public key with a UTC stamp used as a data blob for PublicKeySignature.
struct PublicKeyWithTimestamp {
  key       @0 :PublicKey;
  utcstamp  @1 :Int64;
}

# Signed public key.
struct PublicKeySignature {
  # The key id of the signed key.
  keyId     @0 :KeyId;
  # The public key of the signer used for verification of the signature.
  signer    @1 :PublicKey;
  # A checksum of the signature.
  checksum  @2 :Blake2b64;
  # Signature of a PublicKeyWithTimestamp. Note that if URL changes, the key
  # would require re-signing.
  signature @3 :Data;
}

# An entry describing signature or revocation of the public keys.
#
# While these entries are not signed by the owner, the signature is required
# when extracting the logs. Even in the event of a compromised key, malicious
# actor won't put arbitrary log entries due to passphrase requirement
# to unseal the secret key for signing.
#
# UTCStamp indicates when the entry has been added. Revoked and signed
# timestamps can be back-filled.
struct SignatureLogEntry {
  union {
    signature  @0 :SignatureEntry;
    revocation @1 :RevocationEntry;
  }
  struct SignatureEntry {
    key      @0 :PublicKeyWithTimestamp;
    utcstamp @1 :Int64;
  }
  struct RevocationEntry {
    keyId    @0 :KeyId;
    revoked  @1 :Int64;
    utcstamp @2 :Int64;
  }
}

# An arbitrary messaged signed by a secret key, to be used for exchanging.
struct SignedMessage {
  # Public key of the signer.
  key       @0 :PublicKey;
  # The timestamp of a signature.
  utcstamp  @1 :Int64;
  # A checksum of the original unsigned message.
  checksum  @2 :Blake2b64;
  # Optional signature when signing in detached mode.
  signature @3 :Data;
  # Optional signed data when signing in compound mode.
  data      @4 :Data;
}

# An arbitrary message encrypted to multiple recipients with a shared key
# encrypted by the public key of a recipient.
struct EncryptedMessage {
  # Recipients define which keys can decrypt the message.
  recipients @0 :List(Recipient);
  # Message encrypted by a symmetric key.
  data       @1 :Data;

  struct Recipient {
    # The key id of the key used for asymmetric encryption of recipient fields.
    keyId         @0 :KeyId;
    # The asymmetrically encrypted symmetric key used to decrypt the data.
    encryptionKey @1 :Data;
    # Additional state for the decryption, where each field is encrypted by the
    # public key.
    state         @2 :XChaCha20Poly1305;
  }

  struct XChaCha20Poly1305 {
    nonce @0 :Data;
    tag   @1 :Data;
   }
}

struct Blake2b64 {
  digest @0 :Data;
}

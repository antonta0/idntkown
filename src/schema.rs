use std::fmt;
use std::io;

use alkali::{asymmetric, hash, symmetric};

use crate::schema_v1_capnp::{
    encrypted_data, encrypted_message, header, key_id, public_key, public_key_signature,
    public_key_with_timestamp, secret_key, signature_log_entry, signed_message,
};
use crate::utcstamp::UTCStamp;

/// Something, that can be encoded into capnp bytes.
pub trait ToCapnpBytes {
    /// Encodes this message as capnp bytes and writes it to `writer`.
    ///
    /// # Errors
    ///
    /// If capnp encounters an error during encoding, an error is returned.
    fn to_capnp_bytes<W: io::Write>(&self, writer: W) -> Result<(), capnp::Error>;
}

/// Something that can be decoded from capnp bytes.
pub trait TryFromCapnpBytes
where
    Self: Sized,
{
    /// Decodes a message from capnp bytes.
    ///
    /// # Errors
    ///
    /// If capnp encounters an error during decoding, an error is returned.
    fn try_from_capnp_bytes(bytes: &[u8]) -> Result<Self, capnp::Error>;
}

/// A convenience macro to implement encoding and deconding of capnp bytes.
macro_rules! capnp_bytes_impls {
    ($ty:ty, $msg:tt) => {
        impl ToCapnpBytes for $ty {
            fn to_capnp_bytes<W: io::Write>(&self, writer: W) -> Result<(), capnp::Error> {
                let mut builder = capnp::message::Builder::new_default();
                let mut message = builder.init_root::<$msg::Builder>();
                self.copy_into_capnp(&mut message);
                let mut canonical = capnp::message::Builder::new_default();
                canonical.set_root_canonical(message.into_reader())?;
                capnp::serialize::write_message(writer, &canonical)
            }
        }

        impl TryFromCapnpBytes for $ty {
            fn try_from_capnp_bytes(bytes: &[u8]) -> Result<$ty, capnp::Error> {
                let reader = capnp::message::Reader::new(
                    capnp::serialize::NoAllocBufferSegments::from_buffer(
                        bytes,
                        capnp::message::ReaderOptions::default(),
                    )?,
                    capnp::message::ReaderOptions::default(),
                );
                reader.get_root::<$msg::Reader>()?.try_into()
            }
        }
    };
}

/// An error encountered during signing.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SignError {
    /// Secret key is sealed and has to be unsealed before signing.
    Sealed,
    /// Signature of arbitrary bytes failed for whatever reason.
    SigningFailed,
}

impl std::error::Error for SignError {}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::Sealed => {
                write!(f, "secret key is sealed")
            }
            SignError::SigningFailed => {
                write!(f, "signing failed")
            }
        }
    }
}

/// An error encountered during verification of a signature.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerifyError {
    /// Algorithm is not supported by this implementation.
    AlgorithmUnrecognized,
    /// Size of signature bytes is incorrect.
    MalformedSignature,
    /// Checksum of the bytes signed does not match after verification of a signature.
    ChecksumMismatch,
    /// Verificaation of arbitrary bytes failed for whatever reason.
    VerificationFailed,
}

impl std::error::Error for VerifyError {}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::AlgorithmUnrecognized => {
                write!(f, "public key algorithm is not recognized")
            }
            VerifyError::MalformedSignature => {
                write!(f, "detached signature is malformed")
            }
            VerifyError::ChecksumMismatch => {
                write!(f, "checksum does not match the original message")
            }
            VerifyError::VerificationFailed => {
                write!(f, "signature verification failed")
            }
        }
    }
}

/// An error encountered during encryption of arbitrary bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EncryptError {
    /// Algorithm is not supported by this implementation.
    AlgorithmUnrecognized,
    /// Conversion between key curves failed.
    KeyConversionFailed,
}

impl std::error::Error for EncryptError {}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptError::AlgorithmUnrecognized => {
                write!(f, "public key algorithm is not recognized")
            }
            EncryptError::KeyConversionFailed => {
                write!(f, "conversion between public key curves failed")
            }
        }
    }
}

/// An error encountered during encryption of arbitrary bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DecryptError {
    /// Secret key is sealed and has to be unsealed before decrypting.
    Sealed,
    /// Conversion between key curves failed.
    KeyConversionFailed,
    /// Message format used for encryption is malformed.
    Malformed,
    /// Decryption failed for whatever reason.
    DecryptionFailed,
}

impl std::error::Error for DecryptError {}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptError::Sealed => {
                write!(f, "secret key is sealed")
            }
            DecryptError::KeyConversionFailed => {
                write!(f, "conversion between secret key curves failed")
            }
            DecryptError::Malformed => {
                write!(f, "message is malformed")
            }
            DecryptError::DecryptionFailed => {
                write!(f, "decryption failed: input or secret key are incorrect")
            }
        }
    }
}

/// An error encountered during importing of PGP key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PGPImportError {
    /// Algorithm is not supported by this implementation.
    AlgorithmUnrecognized,
    /// The secret key imported is encrypted.
    SecretKeyEncrypted,
}

impl std::error::Error for PGPImportError {}

impl fmt::Display for PGPImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PGPImportError::AlgorithmUnrecognized => {
                write!(f, "pgp key algorithm is not supported")
            }
            PGPImportError::SecretKeyEncrypted => {
                write!(f, "only unencrypted pgp keys can be imported")
            }
        }
    }
}

/// Algorithm for the public-private cryptography.
#[derive(Copy, Clone, Debug)]
enum KeyAlgorithm {
    Ed25519 = 1,
}

impl KeyAlgorithm {
    /// Converts the enum variant into `Meta` bits.
    #[inline(always)]
    fn as_meta(self) -> u64 {
        (self as u64) << Meta::VERSION_BITS
    }
}

impl TryFrom<u64> for KeyAlgorithm {
    type Error = ();

    #[inline(always)]
    fn try_from(value: u64) -> Result<KeyAlgorithm, ()> {
        match value {
            0b0001 => Ok(KeyAlgorithm::Ed25519),
            _ => Err(()),
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyAlgorithm::Ed25519 => {
                write!(f, "ed25519")
            }
        }
    }
}

/// An unencrypted secret key of a corresponding algorithm.
enum UnsealedSecretKey {
    Ed25519(asymmetric::sign::ed25519::PrivateKey<alkali::mem::FullAccess>),
}

impl AsRef<[u8]> for UnsealedSecretKey {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        match self {
            UnsealedSecretKey::Ed25519(key) => key.as_ref(),
        }
    }
}

impl AsMut<[u8]> for UnsealedSecretKey {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            UnsealedSecretKey::Ed25519(key) => key.as_mut(),
        }
    }
}

/// A mode to use when generating an arbitrary byte sequence signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SignatureMode {
    /// The signature and the data are stored together.
    Compound,
    /// The signature is stored separately from the data.
    Detached,
}

/// Key identifier, expressed as a `BLAKE2b` sum of the public key bytes of
/// 32 bytes in size.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(pub [u8; Self::KEY_ID_SIZE]);

impl KeyId {
    const KEY_ID_SIZE: usize = 32;

    /// Constructs a new `KeyId` from a sequence of bytes by taking a hash.
    fn from_bytes(bytes: &[u8]) -> KeyId {
        let mut key_id = [0u8; Self::KEY_ID_SIZE];
        hash::generic::blake2b::hash_custom(bytes, None, &mut key_id)
            .expect("length is statically defined");
        KeyId(key_id)
    }

    /// Copies the `KeyId` into the corresponding capnp message.
    fn copy_into_capnp(&self, message: &mut key_id::Builder<'_>) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.0[0..8]);
        message.set_bytes1(u64::from_be_bytes(buf));
        buf.copy_from_slice(&self.0[8..16]);
        message.set_bytes2(u64::from_be_bytes(buf));
        buf.copy_from_slice(&self.0[16..24]);
        message.set_bytes3(u64::from_be_bytes(buf));
        buf.copy_from_slice(&self.0[24..32]);
        message.set_bytes4(u64::from_be_bytes(buf));
    }
}

impl<'data> From<key_id::Reader<'data>> for KeyId {
    fn from(value: key_id::Reader<'data>) -> KeyId {
        let mut bytes = [0u8; Self::KEY_ID_SIZE];
        bytes[0..8].copy_from_slice(&value.get_bytes1().to_be_bytes());
        bytes[8..16].copy_from_slice(&value.get_bytes2().to_be_bytes());
        bytes[16..24].copy_from_slice(&value.get_bytes3().to_be_bytes());
        bytes[24..32].copy_from_slice(&value.get_bytes4().to_be_bytes());
        KeyId(bytes)
    }
}

impl<'data> TryFrom<&'data str> for KeyId {
    type Error = ();

    fn try_from(value: &'data str) -> Result<KeyId, ()> {
        let mut bytes = [0u8; Self::KEY_ID_SIZE];
        alkali::encode::hex::decode(value, &mut bytes).map_err(|_| ())?;
        Ok(KeyId(bytes))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "keyid:{}",
            alkali::encode::hex::encode(&self.0).expect("libsodium initialization failure")
        )
    }
}

/// Metadata section of the key. 8 bits are used for the version of the binary
/// generated the key, 4 bits for the algorithms, the remaining 52 bits are
/// reserved for later use.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
struct Meta(u64);

impl Meta {
    const VERSION_BITS: u32 = 8;
    const ALGORITHM_BITS: u32 = 4;

    const VERSION_MASK: u64 = (1 << Self::VERSION_BITS) - 1;
    const ALGORITHM_MASK: u64 = ((1 << Self::ALGORITHM_BITS) - 1) << Self::VERSION_BITS;

    // TODO: Add compile-time macro here to increment the version.
    const VERSION: u64 = 0b0000_0001;

    /// Initializes a new instance of `Meta` with the current version and a given
    /// algorithm.
    #[inline(always)]
    #[must_use]
    fn new(algorithm: KeyAlgorithm) -> Meta {
        Meta(Meta::VERSION | algorithm.as_meta())
    }

    /// A version stored in this `Meta`.
    #[inline(always)]
    fn version(self) -> u64 {
        self.0 & Self::VERSION_MASK
    }

    /// An algorithm stored in this `Meta`.
    #[inline(always)]
    fn algorithm(self) -> u64 {
        (self.0 & Self::ALGORITHM_MASK) >> Self::VERSION_BITS
    }
}

/// `Header` is can be thought of metadata of a public or a secret key. This
/// type correponds to the Header capnp struct.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Header {
    key_id: KeyId,
    meta: Meta,
    utcstamp: UTCStamp,
}

impl Header {
    /// Constructs a new `Header`.
    fn new(key_id: KeyId, meta: Meta, utcstamp: UTCStamp) -> Header {
        Header {
            key_id,
            meta,
            utcstamp,
        }
    }

    /// Copies the `Header` into the corresponding capnp message.
    fn copy_into_capnp(&self, message: &mut header::Builder<'_>) {
        let mut key_id = message.reborrow().init_key_id();
        self.key_id.copy_into_capnp(&mut key_id);
        message.set_meta(self.meta.0);
        message.set_utcstamp(self.utcstamp.0);
    }
}

impl<'data> TryFrom<header::Reader<'data>> for Header {
    type Error = capnp::Error;

    fn try_from(value: header::Reader<'data>) -> Result<Header, capnp::Error> {
        Ok(Header::new(
            value.get_key_id()?.into(),
            Meta(value.get_meta()),
            UTCStamp(value.get_utcstamp()),
        ))
    }
}

/// A secret key of the public-secret key pair. The key itself is sealed when
/// written to disk and is unsealed in memory only when necessary.
///
/// The metadata of a this key matches the corresponding `PublicKey`.
pub struct SecretKey {
    header: Header,
    label: String,
    encrypted_key: capnp::message::TypedBuilder<encrypted_data::Owned>,
    key: Option<UnsealedSecretKey>,
    url: Option<String>,
}

impl SecretKey {
    /// Constructs a new `SecretKey` with unsealed secret key.
    fn new(header: Header, label: &str, key: UnsealedSecretKey, url: Option<&str>) -> SecretKey {
        let sk = SecretKey {
            header,
            label: label.to_string(),
            encrypted_key: capnp::message::TypedBuilder::<encrypted_data::Owned>::new_default(),
            key: Some(key),
            url: url.map(std::string::ToString::to_string),
        };
        assert_eq!(
            sk.header.key_id,
            KeyId::from_bytes(&sk.public_key().unwrap().key),
            "key id does not match the public key"
        );
        sk
    }

    /// Whether the key is unsealed.
    #[inline(always)]
    fn is_unsealed(&self) -> bool {
        self.key.is_some()
    }

    /// Seals the secret key with the provided password.
    ///
    /// The password is used as an input to the key derivation function. Both
    /// salt of the password and nonce for the symmetric key encryption are
    /// shared and generated uniquely for every seal operation.
    #[allow(clippy::missing_panics_doc)]
    pub fn seal(&mut self, password: &[u8]) {
        let salt = hash::pbkdf::scrypt::generate_salt().expect("libsodium initialization failure");
        let mut encryption_key = symmetric::cipher::xchacha20poly1305::Key::new_empty()
            .expect("libsodium initialization or malloc failure");
        hash::pbkdf::scrypt::derive_key(
            password,
            &salt,
            hash::pbkdf::scrypt::OPS_LIMIT_SENSITIVE,
            hash::pbkdf::scrypt::MEM_LIMIT_SENSITIVE,
            encryption_key.as_mut_slice(),
        )
        .expect("password too long?");

        let unsealed_key = self
            .key
            .as_ref()
            .expect("call to seal without unseal")
            .as_ref();
        let mut encrypted_data = match self.key.as_ref().unwrap() {
            UnsealedSecretKey::Ed25519(_) => [0u8; asymmetric::sign::ed25519::PRIVATE_KEY_LENGTH],
        };
        let (n, _, tag) = symmetric::cipher::xchacha20poly1305::encrypt_detached(
            unsealed_key,
            &encryption_key,
            Some(&core::array::from_fn::<
                u8,
                { symmetric::cipher::xchacha20poly1305::NONCE_LENGTH },
                _,
            >(|n| salt[n])),
            &mut encrypted_data,
        )
        .expect("bytes slices of equal size");
        assert_eq!(n, encrypted_data.len());

        let mut encrypted_key = self.encrypted_key.init_root();
        encrypted_key.reborrow().set_data(&encrypted_data);
        let mut state = encrypted_key.init_state();
        state.reborrow().set_salt(&salt);
        state.set_tag(&tag);

        self.key.take();
    }

    /// Unseals the secret key with the provided password.
    ///
    /// This is the inverse of [`SecretKey::seal`], where key for symmetric
    /// encryption is derived from the password and stored salt.
    ///
    /// # Errors
    ///
    /// Returns [`capnp::Error`] of [`capnp::ErrorKind::Failed`] if unseal
    /// is called without prior seal, or the encrypted key structure is
    /// malformed.
    #[allow(clippy::missing_panics_doc)]
    pub fn unseal(&mut self, password: &[u8]) -> Result<(), capnp::Error> {
        let message = self.encrypted_key.get_root_as_reader()?;
        if !message.has_data() {
            return Err(capnp::Error::failed(String::from(
                "encrypted data is missing: unseal without seal?",
            )));
        }

        let state = message.get_state()?;
        if !state.has_salt() {
            return Err(capnp::Error::failed(String::from(
                "salt is missing - unseal without seal?",
            )));
        }
        let mut salt = [0u8; hash::pbkdf::scrypt::SALT_LENGTH];
        salt.copy_from_slice(state.get_salt()?);
        let mut encryption_key = symmetric::cipher::xchacha20poly1305::Key::new_empty()
            .expect("libsodium initialization or malloc failure");
        hash::pbkdf::scrypt::derive_key(
            password,
            &salt,
            hash::pbkdf::scrypt::OPS_LIMIT_SENSITIVE,
            hash::pbkdf::scrypt::MEM_LIMIT_SENSITIVE,
            encryption_key.as_mut_slice(),
        )
        .expect("password too long?");
        if !state.has_tag() {
            return Err(capnp::Error::failed(String::from(
                "tag is missing - unseal without seal?",
            )));
        }
        let tag = state.get_tag()?;
        let tag =
            &core::array::from_fn::<u8, { symmetric::cipher::xchacha20poly1305::MAC_LENGTH }, _>(
                |n| tag[n],
            );

        match self
            .header
            .meta
            .algorithm()
            .try_into()
            .map_err(|()| capnp::Error::failed(String::from("unsupported algorithm")))?
        {
            KeyAlgorithm::Ed25519 => {
                let key = self.key.get_or_insert(UnsealedSecretKey::Ed25519(
                    asymmetric::sign::ed25519::PrivateKey::new_empty()
                        .expect("libsodium initialization or malloc failure"),
                ));
                match key {
                    UnsealedSecretKey::Ed25519(key) => {
                        key.zero().expect("libsodium initialization failure");
                    }
                };
            }
        }
        let n = symmetric::cipher::xchacha20poly1305::decrypt_detached(
            message.get_data()?,
            tag,
            &encryption_key,
            &core::array::from_fn::<u8, { symmetric::cipher::xchacha20poly1305::NONCE_LENGTH }, _>(
                |n| salt[n],
            ),
            self.key.as_mut().unwrap().as_mut(),
        )
        .map_err(|_| {
            self.key.take();
            capnp::Error::failed(String::from("failed to unseal - bad password?"))
        })?;
        assert_eq!(n, message.get_data()?.len());
        assert_eq!(
            self.header.key_id,
            KeyId::from_bytes(&self.public_key().unwrap().key),
            "key id does not match the public key"
        );
        Ok(())
    }

    /// Signs a public key with this secret key.
    ///
    /// This is a special kind of signature which stores the timestamp of the
    /// signature within the signed public key message. The timestamp can be
    /// provided from the "past" if, say, the key has to be re-signed.
    ///
    /// # Errors
    ///
    /// If the secret key is sealed, [`SignError::Sealed`] is returned.
    #[allow(clippy::missing_panics_doc)]
    pub fn sign_public_key(
        &self,
        key: &PublicKey,
        utcstamp: UTCStamp,
    ) -> Result<PublicKeySignature, SignError> {
        if self.key.is_none() {
            return Err(SignError::Sealed);
        }

        let key_with_timestamp = PublicKeyWithTimestamp::new(key.clone(), utcstamp);
        let mut bytes = Vec::new();
        key_with_timestamp
            .to_capnp_bytes(&mut bytes)
            .expect("encoding to capnp should always succeed");
        match self.key.as_ref().unwrap() {
            UnsealedSecretKey::Ed25519(secret_key) => {
                let keypair = asymmetric::sign::ed25519::Keypair::from_private_key(secret_key)
                    .expect("libsodium initialization or malloc failure");
                let mut signature =
                    vec![0u8; bytes.len() + asymmetric::sign::ed25519::SIGNATURE_LENGTH];
                asymmetric::sign::ed25519::sign(&bytes, &keypair, &mut signature)
                    .expect("output of sufficient size");
                Ok(PublicKeySignature::new(
                    key.header.key_id,
                    PublicKey::new(
                        self.header.clone(),
                        &self.label,
                        keypair.public_key.as_ref(),
                        self.url.as_deref(),
                    ),
                    signature,
                ))
            }
        }
    }

    /// Signs an arbitrary sequence of bytes either in detached or compound mode,
    /// returning the detached or compound signature respectively.
    ///
    /// # Errors
    ///
    /// If the secret key is sealed, [`SignError::Sealed`] is returned.
    /// If for whatever reason signing fails, [`SignError::SigningFailed`] error
    /// is returned.
    fn sign(&self, bytes: &[u8], mode: SignatureMode) -> Result<Vec<u8>, SignError> {
        if self.key.is_none() {
            return Err(SignError::Sealed);
        }

        match self.key.as_ref().unwrap() {
            UnsealedSecretKey::Ed25519(key) => {
                let keypair = asymmetric::sign::ed25519::Keypair::from_private_key(key)
                    .expect("libsodium initialization or malloc failure");
                match mode {
                    SignatureMode::Compound => {
                        let mut signature =
                            vec![0u8; bytes.len() + asymmetric::sign::ed25519::SIGNATURE_LENGTH];
                        asymmetric::sign::ed25519::sign(bytes, &keypair, &mut signature)
                            .map_err(|_| SignError::SigningFailed)?;
                        Ok(signature)
                    }
                    SignatureMode::Detached => {
                        let signature = asymmetric::sign::ed25519::sign_detached(bytes, &keypair)
                            .map_err(|_| SignError::SigningFailed)?;
                        Ok(signature.0.to_vec())
                    }
                }
            }
        }
    }

    /// Decrypts an arbitrary sequence of bytes, returning the decrypted bytes.
    ///
    /// This function derives curve25519 from the secret ed25519 key to use for
    /// decryption.
    ///
    /// # Errors
    ///
    /// If the secret key is sealed, [`DecryptError::Sealed`] is returned.
    /// If conversion from ed25519 to curve25519 fails,
    /// [`DecryptError::KeyConversionFailed`] error is returned.
    /// If decryption fails, [`DecryptError::DecryptionFailed`] error is returned.
    fn decrypt(&self, bytes: &[u8]) -> Result<Vec<u8>, DecryptError> {
        match self.key.as_ref().ok_or(DecryptError::Sealed)? {
            UnsealedSecretKey::Ed25519(key) => {
                let mut scalar = alkali::curve::ed25519::Scalar::new_empty()
                    .expect("libsodium initialization or malloc failure");
                scalar.copy_from_slice(&key.as_ref()[..alkali::curve::ed25519::SCALAR_LENGTH]);
                let mut key =
                    asymmetric::seal::curve25519xchacha20poly1305::PrivateKey::new_empty()
                        .expect("libsodium initialization or malloc failure");
                key.copy_from_slice(
                    scalar
                        .to_curve25519()
                        .map_err(|_| DecryptError::KeyConversionFailed)?
                        .as_ref(),
                );
                let keypair =
                    asymmetric::seal::curve25519xchacha20poly1305::Keypair::from_private_key(&key)
                        .expect("libsodium initialization or malloc failure");
                let mut decrypted = vec![
                    0u8;
                    bytes.len().saturating_sub(
                        asymmetric::seal::curve25519xchacha20poly1305::OVERHEAD_LENGTH
                    )
                ];
                let n = asymmetric::seal::curve25519xchacha20poly1305::decrypt(
                    bytes,
                    &keypair,
                    &mut decrypted,
                )
                .map_err(|err| match err {
                    alkali::AlkaliError::SealError(
                        asymmetric::seal::SealError::DecryptionFailed,
                    ) => DecryptError::DecryptionFailed,
                    alkali::AlkaliError::SodiumInitFailed => {
                        panic!("libsodium initialization failure")
                    }
                    _ => unreachable!("unexpected error: {err}"),
                })?;
                assert_eq!(n, decrypted.len());
                Ok(decrypted)
            }
        }
    }

    /// Derives a public key from this secret key.
    fn public_key(&self) -> Option<PublicKey> {
        match self.key.as_ref()? {
            UnsealedSecretKey::Ed25519(key) => Some(PublicKey::new(
                self.header.clone(),
                &self.label,
                asymmetric::sign::ed25519::Keypair::from_private_key(key)
                    .expect("libsodium initialization or malloc failure")
                    .public_key
                    .as_ref(),
                self.url.as_deref(),
            )),
        }
    }

    /// Copies the `SecretKey` into the corresponding capnp message.
    ///
    /// Requires the key to be sealed.
    fn copy_into_capnp(&self, message: &mut secret_key::Builder<'_>) {
        let encrypted_key = self
            .encrypted_key
            .get_root_as_reader()
            .expect("encrypted key should be initialized: seal must be called before serializing");
        assert!(
            encrypted_key.has_data(),
            "encrypted data is missing: seal must be called before serializing"
        );
        let mut header = message.reborrow().init_header();
        self.header.copy_into_capnp(&mut header);
        message.set_label(capnp::text::Reader::from(self.label.as_bytes()));
        message
            .set_key(encrypted_key)
            .expect("setting struct pointer should always succeed");
        if let Some(url) = self.url.as_ref() {
            message.set_url(capnp::text::Reader::from(url.as_bytes()));
        }
    }
}

capnp_bytes_impls!(SecretKey, secret_key);

impl<'data> TryFrom<secret_key::Reader<'data>> for SecretKey {
    type Error = capnp::Error;

    fn try_from(value: secret_key::Reader<'data>) -> Result<SecretKey, capnp::Error> {
        let mut encrypted_key =
            capnp::message::TypedBuilder::<encrypted_data::Owned>::new_default();
        encrypted_key.set_root(value.get_key()?)?;
        Ok(SecretKey {
            header: value.get_header()?.try_into()?,
            label: value
                .get_label()?
                .to_string()
                .expect("label is utf8 encoded"),
            encrypted_key,
            key: None,
            url: if value.has_url() {
                Some(value.get_url()?.to_string().expect("url is utf8 encoded"))
            } else {
                None
            },
        })
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algorithm: KeyAlgorithm = self
            .header
            .meta
            .algorithm()
            .try_into()
            .map_err(|()| fmt::Error)?;
        writeln!(
            f,
            "sec:{}:v{} {}",
            algorithm,
            self.header.meta.version(),
            self.header.key_id,
        )?;
        write!(f, "    {} @{}", self.label, self.header.utcstamp,)?;
        if let Some(url) = self.url.as_ref() {
            write!(f, "  {url}",)?;
        }
        Ok(())
    }
}

/// A public portion of the public-secret key pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    header: Header,
    label: String,
    key: Vec<u8>,
    url: Option<String>,
}

impl PublicKey {
    /// Constructs a new `PublicKey`.
    fn new(header: Header, label: &str, key: &[u8], url: Option<&str>) -> PublicKey {
        PublicKey {
            header,
            label: label.to_string(),
            key: key.to_vec(),
            url: url.map(std::string::ToString::to_string),
        }
    }

    /// Returns a key id of this public key.
    #[inline(always)]
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.header.key_id
    }

    /// Verifies a signature of an arbitrary sequence of bytes in compound mode,
    /// returning the signed data back to the caller on success.
    ///
    /// # Errors
    ///
    /// If the public key has unsupported algorithm,
    /// [`VerifyError::AlgorithmUnrecognized`] is returned. Otherwise, if
    /// verification fails for whatever reason,
    /// [`VerifyError::VerificationFailed`] error is returned.
    fn verify_compound(&self, bytes: &[u8]) -> Result<Vec<u8>, VerifyError> {
        match self
            .header
            .meta
            .algorithm()
            .try_into()
            .map_err(|()| VerifyError::AlgorithmUnrecognized)?
        {
            KeyAlgorithm::Ed25519 => Ok(asymmetric::sign::ed25519::verify(
                bytes,
                &core::array::from_fn::<u8, { asymmetric::sign::ed25519::PUBLIC_KEY_LENGTH }, _>(
                    |n| self.key[n],
                ),
            )
            .map_err(|_| VerifyError::VerificationFailed)?
            .to_vec()),
        }
    }

    /// Verifies a signature of an arbitrary sequence of bytes in detached mode.
    ///
    /// # Errors
    ///
    /// If the public key has unsupported algorithm,
    /// [`VerifyError::AlgorithmUnrecognized`] is returned. Otherwise, if
    /// verification fails for whatever reason,
    /// [`VerifyError::VerificationFailed`] error is returned.
    fn verify_detached(&self, bytes: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        match self
            .header
            .meta
            .algorithm()
            .try_into()
            .map_err(|()| VerifyError::AlgorithmUnrecognized)?
        {
            KeyAlgorithm::Ed25519 => {
                if signature.len() != asymmetric::sign::ed25519::SIGNATURE_LENGTH {
                    return Err(VerifyError::MalformedSignature);
                }
                asymmetric::sign::ed25519::verify_detached(
                        bytes,
                        &asymmetric::sign::ed25519::Signature(core::array::from_fn::<
                            u8,
                            { asymmetric::sign::ed25519::SIGNATURE_LENGTH },
                            _,
                        >(|n| {
                            signature[n]
                        })),
                        &core::array::from_fn::<
                            u8,
                            { asymmetric::sign::ed25519::PUBLIC_KEY_LENGTH },
                            _,
                        >(|n| self.key[n]),
                    )
                    .map_err(|_| VerifyError::VerificationFailed)
            }
        }
    }

    /// Encrypts an arbitrary sequence of bytes, returning the encrypted data
    /// on success.
    ///
    /// # Errors
    ///
    /// If the public key has unsupported algorithm,
    /// [`VerifyError::AlgorithmUnrecognized`] is returned. If key conversion
    /// from ed25519 to curve25519 fails, [`EncryptError::KeyConversionFailed`]
    /// error is returned.
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>, EncryptError> {
        match self
            .header
            .meta
            .algorithm()
            .try_into()
            .map_err(|()| EncryptError::AlgorithmUnrecognized)?
        {
            KeyAlgorithm::Ed25519 => {
                let mut encrypted = vec![
                    0u8;
                    bytes.len().saturating_add(
                        asymmetric::seal::curve25519xchacha20poly1305::OVERHEAD_LENGTH
                    )
                ];
                asymmetric::seal::curve25519xchacha20poly1305::encrypt(
                    bytes,
                    &alkali::curve::ed25519::Point(core::array::from_fn::<
                        u8,
                        { asymmetric::sign::ed25519::PUBLIC_KEY_LENGTH },
                        _,
                    >(|n| self.key[n]))
                    .to_curve25519()
                    .map_err(|_| EncryptError::KeyConversionFailed)?
                    .0,
                    &mut encrypted,
                )
                .expect("bytes too long");
                Ok(encrypted)
            }
        }
    }

    /// Copies the `PublicKey` into the corresponding capnp message.
    fn copy_into_capnp(&self, message: &mut public_key::Builder<'_>) {
        let mut header = message.reborrow().init_header();
        self.header.copy_into_capnp(&mut header);
        message.set_label(capnp::text::Reader::from(self.label.as_bytes()));
        let key = message.reborrow().init_key(
            self.key
                .len()
                .try_into()
                .expect("key size never exceeds 4GiB"),
        );
        key.copy_from_slice(&self.key);
        if let Some(url) = self.url.as_ref() {
            message.set_url(capnp::text::Reader::from(url.as_bytes()));
        }
    }
}

capnp_bytes_impls!(PublicKey, public_key);

impl<'data> TryFrom<public_key::Reader<'data>> for PublicKey {
    type Error = capnp::Error;

    fn try_from(value: public_key::Reader<'data>) -> Result<PublicKey, capnp::Error> {
        let url = if value.has_url() {
            Some(value.get_url()?.to_string().expect("url is utf8 encoded"))
        } else {
            None
        };
        Ok(PublicKey::new(
            value.get_header()?.try_into()?,
            value.get_label()?.to_str().expect("label is utf8 encoded"),
            value.get_key()?,
            url.as_deref(),
        ))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algorithm: KeyAlgorithm = self
            .header
            .meta
            .algorithm()
            .try_into()
            .map_err(|()| fmt::Error)?;
        writeln!(
            f,
            "pub:{}:v{} {}",
            algorithm,
            self.header.meta.version(),
            self.header.key_id,
        )?;
        write!(f, "    {} @{}", self.label, self.header.utcstamp,)?;
        if let Some(url) = self.url.as_ref() {
            write!(f, "  {url}",)?;
        }
        Ok(())
    }
}

/// A [`PublicKey`], yet with a utcstamp along with it. This type is used for
/// signing public keys.
#[derive(Clone)]
pub struct PublicKeyWithTimestamp {
    key: PublicKey,
    utcstamp: UTCStamp,
}

impl PublicKeyWithTimestamp {
    /// Constructs a new `PublicKeyWithTimestamp`.
    fn new(key: PublicKey, utcstamp: UTCStamp) -> PublicKeyWithTimestamp {
        PublicKeyWithTimestamp { key, utcstamp }
    }

    /// Returns the `PublicKey`.
    #[inline(always)]
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    /// Returns the `UTCStamp`.
    #[inline(always)]
    #[must_use]
    pub fn utcstamp(&self) -> UTCStamp {
        self.utcstamp
    }

    /// Copies the `PublicKeyWithTimestamp` into the corresponding capnp message.
    fn copy_into_capnp(&self, message: &mut public_key_with_timestamp::Builder<'_>) {
        let mut key = message.reborrow().init_key();
        self.key.copy_into_capnp(&mut key);
        message.set_utcstamp(self.utcstamp.0);
    }
}

capnp_bytes_impls!(PublicKeyWithTimestamp, public_key_with_timestamp);

impl<'data> TryFrom<public_key_with_timestamp::Reader<'data>> for PublicKeyWithTimestamp {
    type Error = capnp::Error;

    fn try_from(
        value: public_key_with_timestamp::Reader<'data>,
    ) -> Result<PublicKeyWithTimestamp, capnp::Error> {
        Ok(PublicKeyWithTimestamp::new(
            value.get_key()?.try_into()?,
            UTCStamp(value.get_utcstamp()),
        ))
    }
}

/// A signature of a [`PublicKey`].
pub struct PublicKeySignature {
    key_id: KeyId,
    signer: PublicKey,
    checksum: Vec<u8>,
    signature: Vec<u8>,
}

impl PublicKeySignature {
    /// Constructs a new `PublicKeySignature`.
    fn new(key_id: KeyId, signer: PublicKey, signature: Vec<u8>) -> PublicKeySignature {
        let mut checksum = [0u8; hash::generic::blake2b::DIGEST_LENGTH_MAX];
        hash::generic::blake2b::hash_custom(&signature, None, &mut checksum)
            .expect("length is statically defined");
        PublicKeySignature {
            key_id,
            signer,
            checksum: checksum.to_vec(),
            signature,
        }
    }

    /// Returns the key id of the signed key.
    #[inline(always)]
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Returns a reference to a public key of the signer.
    #[inline(always)]
    #[must_use]
    pub fn signer(&self) -> &PublicKey {
        &self.signer
    }

    /// Verifies this signature and returns timestamped public key on success.
    ///
    /// # Errors
    ///
    /// If checksums of the signed data does not match the stored checksum,
    /// a [`VerifyError::ChecksumMismatch`] error is returned.
    /// If the public key has unsupported algorithm,
    /// [`VerifyError::AlgorithmUnrecognized`] is returned. Otherwise, if
    /// verification fails for whatever reason,
    /// [`VerifyError::VerificationFailed`] error is returned.
    #[allow(clippy::missing_panics_doc)]
    pub fn verify(&self) -> Result<PublicKeyWithTimestamp, VerifyError> {
        let mut checksum = [0u8; hash::generic::blake2b::DIGEST_LENGTH_MAX];
        hash::generic::blake2b::hash_custom(&self.signature, None, &mut checksum)
            .expect("length is statically defined");
        if self.checksum != checksum {
            return Err(VerifyError::ChecksumMismatch);
        }
        let bytes = self.signer.verify_compound(&self.signature)?;
        Ok(PublicKeyWithTimestamp::try_from_capnp_bytes(&bytes)
            .expect("signature always encodes PublicKeyWithTimestamp"))
    }

    /// Copies the `PublicKeySignature` into the corresponding capnp message.
    fn copy_into_capnp(&self, message: &mut public_key_signature::Builder<'_>) {
        let mut key_id = message.reborrow().init_key_id();
        self.key_id.copy_into_capnp(&mut key_id);
        let mut signer = message.reborrow().init_signer();
        self.signer.copy_into_capnp(&mut signer);
        let digest = message.reborrow().init_checksum().init_digest(
            self.checksum
                .len()
                .try_into()
                .expect("checksum size never exceeds 4GiB"),
        );
        digest.copy_from_slice(&self.checksum);
        let signature = message.reborrow().init_signature(
            self.signature
                .len()
                .try_into()
                .expect("signature size never exceeds 4GiB"),
        );
        signature.copy_from_slice(&self.signature);
    }
}

capnp_bytes_impls!(PublicKeySignature, public_key_signature);

impl<'data> TryFrom<public_key_signature::Reader<'data>> for PublicKeySignature {
    type Error = capnp::Error;

    fn try_from(
        value: public_key_signature::Reader<'data>,
    ) -> Result<PublicKeySignature, capnp::Error> {
        Ok(PublicKeySignature::new(
            value.get_key_id()?.into(),
            value.get_signer()?.try_into()?,
            value.get_signature()?.to_vec(),
        ))
    }
}

impl fmt::Display for PublicKeySignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algorithm: KeyAlgorithm = self
            .signer
            .header
            .meta
            .algorithm()
            .try_into()
            .map_err(|()| fmt::Error)?;
        let public_key_with_timestamp = self.verify().map_err(|_| fmt::Error)?;
        writeln!(
            f,
            "sig:{}:v{} {}",
            algorithm,
            self.signer.header.meta.version(),
            self.key_id,
        )?;
        write!(
            f,
            "    signed by {} @{}",
            self.signer.header.key_id, public_key_with_timestamp.utcstamp
        )
    }
}

/// An entry indicating a signature or revocation of a public key.
pub enum SignatureLogEntry {
    SignatureEntry {
        key: PublicKeyWithTimestamp,
        utcstamp: UTCStamp,
    },
    RevocationEntry {
        key_id: KeyId,
        revoked: UTCStamp,
        utcstamp: UTCStamp,
    },
}

impl SignatureLogEntry {
    /// Constructs a new signature entry.
    #[must_use]
    pub fn signature_entry(key: PublicKeyWithTimestamp, utcstamp: UTCStamp) -> SignatureLogEntry {
        SignatureLogEntry::SignatureEntry { key, utcstamp }
    }

    /// Constructs a new revocation entry.
    #[must_use]
    pub fn revocation_entry(
        key_id: KeyId,
        revoked: UTCStamp,
        utcstamp: UTCStamp,
    ) -> SignatureLogEntry {
        SignatureLogEntry::RevocationEntry {
            key_id,
            revoked,
            utcstamp,
        }
    }

    /// Copies the `SignatureLogEntry` into the corresponding capnp message.
    fn copy_into_capnp(&self, message: &mut signature_log_entry::Builder<'_>) {
        match self {
            SignatureLogEntry::SignatureEntry { key, utcstamp } => {
                let mut signature = message.reborrow().init_signature();
                signature.set_utcstamp(utcstamp.0);
                let mut key_builder = signature.init_key();
                key.copy_into_capnp(&mut key_builder);
            }
            SignatureLogEntry::RevocationEntry {
                key_id,
                revoked,
                utcstamp,
            } => {
                let mut revocation = message.reborrow().init_revocation();
                revocation.reborrow().set_revoked(revoked.0);
                revocation.reborrow().set_utcstamp(utcstamp.0);
                let mut key_id_builder = revocation.init_key_id();
                key_id.copy_into_capnp(&mut key_id_builder);
            }
        }
    }
}

capnp_bytes_impls!(SignatureLogEntry, signature_log_entry);

impl<'data> TryFrom<signature_log_entry::Reader<'data>> for SignatureLogEntry {
    type Error = capnp::Error;

    fn try_from(
        value: signature_log_entry::Reader<'data>,
    ) -> Result<SignatureLogEntry, capnp::Error> {
        match value.which()? {
            signature_log_entry::Which::Signature(reader) => {
                let reader = reader?;
                Ok(SignatureLogEntry::signature_entry(
                    reader.get_key()?.try_into()?,
                    UTCStamp(reader.get_utcstamp()),
                ))
            }
            signature_log_entry::Which::Revocation(reader) => {
                let reader = reader?;
                Ok(SignatureLogEntry::revocation_entry(
                    reader.get_key_id()?.into(),
                    UTCStamp(reader.get_revoked()),
                    UTCStamp(reader.get_utcstamp()),
                ))
            }
        }
    }
}

impl fmt::Display for SignatureLogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureLogEntry::SignatureEntry { key, utcstamp } => {
                write!(
                    f,
                    "log:signature  {} as of {} @{}",
                    key.key.header.key_id, key.utcstamp, utcstamp
                )
            }
            SignatureLogEntry::RevocationEntry {
                key_id,
                revoked,
                utcstamp,
            } => {
                write!(f, "log:revocation {key_id} as of {revoked} @{utcstamp}",)
            }
        }
    }
}

/// A signed message.
pub struct SignedMessage {
    key: PublicKey,
    utcstamp: UTCStamp,
    checksum: Vec<u8>,
    signature: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
}

impl SignedMessage {
    /// Signs a sequence of bytes with a given secret key and a mode, returning
    /// the `SignedMessage` on success.
    ///
    /// # Errors
    ///
    /// If the secret key is sealed, [`SignError::Sealed`] is returned.
    /// If for whatever reason signing fails, [`SignError::SigningFailed`] error
    /// is returned.
    #[allow(clippy::missing_panics_doc)]
    pub fn sign(
        key: &SecretKey,
        utcstamp: UTCStamp,
        bytes: &[u8],
        mode: SignatureMode,
    ) -> Result<SignedMessage, SignError> {
        let mut checksum = [0u8; hash::generic::blake2b::DIGEST_LENGTH_MAX];
        hash::generic::blake2b::hash_custom(bytes, None, &mut checksum)
            .expect("length is statically defined");

        let data_or_signature = key.sign(bytes, mode)?;
        match mode {
            SignatureMode::Compound => Ok(SignedMessage {
                key: key.public_key().unwrap(),
                utcstamp,
                checksum: checksum.to_vec(),
                signature: None,
                data: Some(data_or_signature),
            }),
            SignatureMode::Detached => Ok(SignedMessage {
                key: key.public_key().unwrap(),
                utcstamp,
                checksum: checksum.to_vec(),
                signature: Some(data_or_signature),
                data: None,
            }),
        }
    }

    /// Returns the public key of the secret key used to sign the message.
    #[inline(always)]
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    /// Returns the timestamp of this signature.
    #[inline(always)]
    #[must_use]
    pub fn utcstamp(&self) -> UTCStamp {
        self.utcstamp
    }

    /// Verifies this signed message in compound mode and returns message on
    /// success.
    ///
    /// # Errors
    ///
    /// If the signed message is not set, [`VerifyError::MalformedSignature`]
    /// is returned. If checksums of the original message does not match what
    /// is stored, [`VerifyError::ChecksumMismatch`] error is returned. If the
    /// public key has unsupported algorithm,
    /// [`VerifyError::AlgorithmUnrecognized`] is returned. Otherwise, if
    /// verification fails for whatever reason,
    /// [`VerifyError::VerificationFailed`] error is returned.
    #[allow(clippy::missing_panics_doc)]
    pub fn verify_compound(&self) -> Result<Vec<u8>, VerifyError> {
        if self.data.is_none() {
            return Err(VerifyError::MalformedSignature);
        }
        let data = self.data.as_ref().unwrap();
        let message = self.key.verify_compound(data)?;
        let mut checksum = [0u8; hash::generic::blake2b::DIGEST_LENGTH_MAX];
        hash::generic::blake2b::hash_custom(&message, None, &mut checksum)
            .expect("length is statically defined");
        if checksum.as_slice() != self.checksum {
            return Err(VerifyError::ChecksumMismatch);
        }
        Ok(message)
    }

    /// Verifies this detached signed message with the sequence of bytes of the
    /// original message.
    ///
    /// # Errors
    ///
    /// If detached signature is not set, [`VerifyError::MalformedSignature`]
    /// is returned. If checksum of the bytes passed does not match what is
    /// stored, [`VerifyError::ChecksumMismatch`] is returned. If the public
    /// key has unsupported algorithm, [`VerifyError::AlgorithmUnrecognized`]
    /// is returned. Otherwise, if verification fails for whatever reason,
    /// [`VerifyError::VerificationFailed`] error is returned.
    #[allow(clippy::missing_panics_doc)]
    pub fn verify_detached(&self, bytes: &[u8]) -> Result<(), VerifyError> {
        if self.signature.is_none() {
            return Err(VerifyError::MalformedSignature);
        }
        let signature = self.signature.as_ref().unwrap();
        let mut checksum = [0u8; hash::generic::blake2b::DIGEST_LENGTH_MAX];
        hash::generic::blake2b::hash_custom(bytes, None, &mut checksum)
            .expect("length is statically defined");
        if checksum.as_slice() != self.checksum {
            return Err(VerifyError::ChecksumMismatch);
        }
        self.key.verify_detached(bytes, signature)
    }

    /// Copies the `SignedMessage` into the corresponding capnp message.
    fn copy_into_capnp(&self, message: &mut signed_message::Builder<'_>) {
        let mut key = message.reborrow().init_key();
        self.key.copy_into_capnp(&mut key);
        message.set_utcstamp(self.utcstamp.0);
        let digest = message.reborrow().init_checksum().init_digest(
            hash::generic::blake2b::DIGEST_LENGTH_MAX
                .try_into()
                .expect("checksum length should not exceed 4GiB"),
        );
        digest.copy_from_slice(&self.checksum);
        if let Some(value) = self.signature.as_ref() {
            let signature = message.reborrow().init_signature(
                value
                    .len()
                    .try_into()
                    .expect("size of signature should not exceed 4GiB"),
            );
            signature.copy_from_slice(value);
        }
        if let Some(value) = self.data.as_ref() {
            let data = message.reborrow().init_data(
                value
                    .len()
                    .try_into()
                    .expect("size of data should not exceed 4GiB"),
            );
            data.copy_from_slice(value);
        }
    }
}

capnp_bytes_impls!(SignedMessage, signed_message);

impl<'data> TryFrom<signed_message::Reader<'data>> for SignedMessage {
    type Error = capnp::Error;

    fn try_from(value: signed_message::Reader<'data>) -> Result<SignedMessage, capnp::Error> {
        Ok(SignedMessage {
            key: value.get_key()?.try_into()?,
            utcstamp: UTCStamp(value.get_utcstamp()),
            checksum: value.get_checksum()?.get_digest()?.to_vec(),
            signature: if value.has_signature() {
                Some(value.get_signature()?.to_vec())
            } else {
                None
            },
            data: if value.has_data() {
                Some(value.get_data()?.to_vec())
            } else {
                None
            },
        })
    }
}

/// An encrypted message to multiple recipients.
pub struct EncryptedMessage {
    recipients: Vec<capnp::message::TypedBuilder<encrypted_message::recipient::Owned>>,
    data: Vec<u8>,
}

impl EncryptedMessage {
    /// Initializes a new instance of `EncryptedMessage`, with `bytes`
    /// encrypted to recipients provided as `pubkeys`.
    ///
    /// # Errors
    ///
    /// If the public keys have unsupported algorithm,
    /// [`VerifyError::AlgorithmUnrecognized`] is returned. If key conversion
    /// from ed25519 to curve25519 fails, [`EncryptError::KeyConversionFailed`]
    /// error is returned.
    #[allow(clippy::missing_panics_doc)]
    pub fn encrypt(pubkeys: &[PublicKey], bytes: &[u8]) -> Result<EncryptedMessage, EncryptError> {
        let encryption_key = symmetric::cipher::xchacha20poly1305::Key::generate()
            .expect("libsodium initialization or malloc failure");
        let nonce = symmetric::cipher::xchacha20poly1305::generate_nonce()
            .expect("libsodium initialization failure");
        let mut encrypted_bytes = vec![0u8; bytes.len()];
        let (n, _, tag) = symmetric::cipher::xchacha20poly1305::encrypt_detached(
            bytes,
            &encryption_key,
            Some(&nonce),
            &mut encrypted_bytes,
        )
        .expect("byte slices of equal size");
        assert_eq!(n, bytes.len());

        let mut recipients = Vec::with_capacity(pubkeys.len());
        for pubkey in pubkeys {
            let mut builder =
                capnp::message::TypedBuilder::<encrypted_message::recipient::Owned>::new_default();
            let mut message = builder.init_root();

            let mut key_id = message.reborrow().init_key_id();
            pubkey.key_id().copy_into_capnp(&mut key_id);

            // Encrypt the symmetric encryption key and store it in the message.
            let encryption_key = pubkey.encrypt(encryption_key.as_ref())?;
            let encryption_key_data = message.reborrow().init_encryption_key(
                encryption_key
                    .len()
                    .try_into()
                    .expect("key size never exceedes 4GiB"),
            );
            encryption_key_data.copy_from_slice(&encryption_key);

            // Encrypt the state necessary for the symmetric encryption.
            let mut state = message.reborrow().init_state();
            let encrypted_nonce = pubkey.encrypt(&nonce)?;
            let nonce_data = state.reborrow().init_nonce(
                encrypted_nonce
                    .len()
                    .try_into()
                    .expect("nonce size never exceeds 4GiB"),
            );
            nonce_data.copy_from_slice(&encrypted_nonce);

            let encrypted_tag = pubkey.encrypt(&tag)?;
            let tag_data = state.reborrow().init_tag(
                encrypted_tag
                    .len()
                    .try_into()
                    .expect("tag size never exceeds 4GiB"),
            );
            tag_data.copy_from_slice(&encrypted_tag);
            recipients.push(builder);
        }
        Ok(EncryptedMessage {
            recipients,
            data: encrypted_bytes,
        })
    }

    /// Decrypts this encrypted message via a secret key and returns the
    /// decrypted bytes on success.
    ///
    /// # Errors
    ///
    /// If the secret key is sealed, [`DecryptError::Sealed`] is returned.
    /// On failure to get a corresponding recipient, or state necessary to
    /// decrypt the message, [`DecryptError::Malformed`] is returned.
    /// Returns [`DecryptError::DecryptionFailed`] if the decryption fails.
    #[allow(clippy::missing_panics_doc)]
    pub fn decrypt(&self, secret_key: &SecretKey) -> Result<Vec<u8>, DecryptError> {
        if !secret_key.is_unsealed() {
            return Err(DecryptError::Sealed);
        }
        for recipient in &self.recipients {
            let recipient = recipient
                .get_root_as_reader()
                .map_err(|_| DecryptError::Malformed)?;
            let key_id: KeyId = recipient
                .get_key_id()
                .map_err(|_| DecryptError::Malformed)?
                .into();
            if key_id == secret_key.header.key_id {
                let state = recipient.get_state().map_err(|_| DecryptError::Malformed)?;

                let mut tag = [0u8; symmetric::cipher::xchacha20poly1305::MAC_LENGTH];
                tag.copy_from_slice(
                    &secret_key.decrypt(state.get_tag().map_err(|_| DecryptError::Malformed)?)?,
                );

                let mut nonce = [0u8; symmetric::cipher::xchacha20poly1305::NONCE_LENGTH];
                nonce.copy_from_slice(
                    &secret_key.decrypt(state.get_nonce().map_err(|_| DecryptError::Malformed)?)?,
                );

                let mut encryption_key = symmetric::cipher::xchacha20poly1305::Key::new_empty()
                    .expect("libsodium initialization or malloc failure");
                encryption_key.copy_from_slice(
                    &secret_key.decrypt(
                        recipient
                            .get_encryption_key()
                            .map_err(|_| DecryptError::Malformed)?,
                    )?,
                );

                let mut decrypted = vec![0u8; self.data.len()];
                symmetric::cipher::xchacha20poly1305::decrypt_detached(
                    &self.data,
                    &tag,
                    &encryption_key,
                    &nonce,
                    &mut decrypted,
                )
                .map_err(|_| DecryptError::DecryptionFailed)?;
                return Ok(decrypted);
            }
        }
        Err(DecryptError::DecryptionFailed)
    }

    /// Copies the `EncryptedMessage` into the corresponding capnp message.
    fn copy_into_capnp(&self, message: &mut encrypted_message::Builder<'_>) {
        let mut recipients = message.reborrow().init_recipients(
            self.recipients
                .len()
                .try_into()
                .expect("number of recipients should not exceed 4294967296"),
        );
        for (n, recipient) in self.recipients.iter().enumerate() {
            recipients
                .set_with_caveats(
                    n.try_into().unwrap(),
                    recipient
                        .get_root_as_reader()
                        .expect("recipients supposed to be initialized"),
                )
                .expect("list is initialized");
        }

        let data = message.reborrow().init_data(
            self.data
                .len()
                .try_into()
                .expect("size of data should not exceed 4GiB"),
        );
        data.copy_from_slice(&self.data);
    }
}

capnp_bytes_impls!(EncryptedMessage, encrypted_message);

impl<'data> TryFrom<encrypted_message::Reader<'data>> for EncryptedMessage {
    type Error = capnp::Error;

    fn try_from(value: encrypted_message::Reader<'data>) -> Result<EncryptedMessage, capnp::Error> {
        let mut recipients = Vec::with_capacity(value.get_recipients()?.len() as usize);
        for recipient in value.get_recipients()? {
            let mut recipient_message =
                capnp::message::TypedBuilder::<encrypted_message::recipient::Owned>::new_default();
            recipient_message.set_root(recipient)?;
            recipients.push(recipient_message);
        }
        Ok(EncryptedMessage {
            recipients,
            data: value.get_data()?.to_vec(),
        })
    }
}

/// Generates a new pair of `SecretKey` and `PublicKey`.
#[allow(clippy::missing_panics_doc)]
#[must_use]
pub fn new_keypair(utcstamp: UTCStamp, label: &str, url: Option<&str>) -> (SecretKey, PublicKey) {
    let keypair = asymmetric::sign::ed25519::Keypair::generate()
        .expect("libsodium initialization or malloc failure");
    let key_id = KeyId::from_bytes(keypair.public_key.as_ref());
    let header = Header::new(key_id, Meta::new(KeyAlgorithm::Ed25519), utcstamp);
    let pk = PublicKey::new(header.clone(), label, keypair.public_key.as_ref(), url);
    let sk = SecretKey::new(
        header,
        label,
        UnsealedSecretKey::Ed25519(keypair.private_key),
        url,
    );
    (sk, pk)
}

/// Imports a primary PGP key into a pair of `SecretKey` and `PublicKey`.
///
/// The primary PGP secret key must be in clear-text (i.e. not encrypted).
///
/// # Errors
///
/// Returns [`PGPImportError::AlgorithmUnrecognized`] if the algorithm of the
/// primary key is unsupported by this implementation.
/// If the primary secret key is encrypted, returns
/// [`PGPImportError::SecretKeyEncrypted`].
#[allow(clippy::missing_panics_doc)]
pub fn import_keypair_from_pgp(
    pgp_key: &pgp::packet::SecretKey,
    label: &str,
    url: Option<&str>,
) -> Result<(SecretKey, PublicKey), PGPImportError> {
    if let pgp::types::secret::SecretParams::Plain(params) = pgp_key.secret_params() {
        match params {
            pgp::types::plain_secret::PlainSecretParams::EdDSA(mpi) => {
                let mut secret_key = alkali::asymmetric::sign::ed25519::PrivateKey::new_empty()
                    .expect("libsodium initialization or malloc failure");
                // The size of a secret key is 32 bytes, the remaining 32 bytes hold
                // the public key.
                secret_key[..alkali::asymmetric::sign::ed25519::PRIVATE_KEY_LENGTH
                    - alkali::asymmetric::sign::ed25519::PUBLIC_KEY_LENGTH]
                    .copy_from_slice(mpi.as_bytes());
                let keypair =
                    alkali::asymmetric::sign::ed25519::Keypair::from_private_key(&secret_key)
                        .expect("libsodium initialization or key conversion failure");
                let key_id = KeyId::from_bytes(keypair.public_key.as_ref());
                let header = Header::new(
                    key_id,
                    Meta::new(KeyAlgorithm::Ed25519),
                    pgp_key.created_at().into(),
                );
                let pk = PublicKey::new(header.clone(), label, keypair.public_key.as_ref(), url);
                let sk = SecretKey::new(
                    header,
                    label,
                    UnsealedSecretKey::Ed25519(keypair.private_key),
                    url,
                );
                Ok((sk, pk))
            }
            _ => Err(PGPImportError::AlgorithmUnrecognized),
        }
    } else {
        Err(PGPImportError::SecretKeyEncrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_from_bytes() {
        let key_id = KeyId::from_bytes(b"1234");
        let expected = KeyId([
            191, 16, 3, 205, 92, 19, 54, 56, 127, 126, 78, 235, 247, 42, 61, 156, 212, 250, 138,
            181, 190, 25, 130, 91, 192, 227, 236, 216, 206, 28, 209, 64,
        ]);
        assert_eq!(key_id, expected);
    }

    #[test]
    fn meta() {
        let case = "bit packing";
        let meta = Meta(0b0100_1010_0101_1111);
        assert_eq!(meta.version(), 0b0101_1111, "{case}");
        assert_eq!(meta.algorithm(), 0b1010, "{case}");

        let case = "normal initialization";
        let meta = Meta::new(KeyAlgorithm::Ed25519);
        assert_eq!(meta.version(), 0b0000_0001, "{case}");
        assert_eq!(meta.algorithm(), 0b0001, "{case}");
    }

    #[test]
    fn secret_key_seal() {
        let (mut sk, _) = test_new_keypair();
        assert_eq!(sk.is_unsealed(), true);
        sk.seal(b"1234");
        assert_eq!(sk.is_unsealed(), false);
        sk.unseal(b"123456")
            .expect_err("unseal with another password");
        assert_eq!(sk.is_unsealed(), false);
        sk.unseal(b"1234").expect("unseal with the same password");
        assert_eq!(sk.is_unsealed(), true);
    }

    #[test]
    fn sign_public_key() {
        let (sk, pk) = test_new_keypair();
        let signed_key = sk
            .sign_public_key(&pk, UTCStamp(2))
            .expect("regular key signature");
        assert_eq!(signed_key.key_id(), pk.key_id());
        assert_eq!(signed_key.signer().key_id(), pk.key_id());
        let key_with_timestamp = signed_key.verify().expect("regular key signature");
        assert_eq!(key_with_timestamp.public_key().key_id(), pk.key_id());
        assert_eq!(key_with_timestamp.utcstamp(), UTCStamp(2));
    }

    #[test]
    fn sign_verify_compound() {
        let (sk, pk) = test_new_keypair();
        let compound_signature = sk
            .sign(&[0x02, 0x04, 0x08, 0x10], SignatureMode::Compound)
            .expect("regular bytes signature");
        let bytes = pk
            .verify_compound(&compound_signature)
            .expect("regular bytes signature");
        assert_eq!(&bytes, &[0x02, 0x04, 0x08, 0x10]);
    }

    #[test]
    fn sign_verify_detached() {
        let (sk, pk) = test_new_keypair();
        let detached_signature = sk
            .sign(&[0x02, 0x04, 0x08, 0x10], SignatureMode::Detached)
            .expect("regular bytes signature");
        pk.verify_detached(&[0x02, 0x04, 0x08, 0x10], &detached_signature)
            .expect("regular bytes signature");
    }

    #[test]
    fn encrypt_decrypt() {
        let (sk, pk) = test_new_keypair();
        let bytes = [0x02, 0x04, 0x08, 0x10];
        let encrypted = pk.encrypt(&bytes).expect("regular bytes encryption");
        assert_ne!(bytes.as_slice(), encrypted.as_slice());
        let decrypted = sk.decrypt(&encrypted).expect("regular bytes decryption");
        assert_eq!(bytes.as_slice(), decrypted.as_slice());
    }

    fn test_new_keypair() -> (SecretKey, PublicKey) {
        new_keypair(UTCStamp(1), "test", None)
    }
}

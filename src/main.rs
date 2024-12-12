use std::{
    io,
    io::{Read, Write},
};

use clap::{Parser, Subcommand, ValueEnum};

use idntkown::schema::{ToCapnpBytes, TryFromCapnpBytes};

/// 64 blocks of 2^12 bytes per block - should be sufficient to store
/// approximately 500 or more entries of ed25519 keys.
const IDNTKOWN_BLOCK_COUNT: u64 = 64;

/// Keypair algorithm supported by the CLI.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum KeypairAlgorithm {
    Ed25519,
}

/// IdntkownFile is a [`pstream::BlockStream`] backed by a regular file.
struct IdntkownFile {
    blockstream: pstream::BlockStream<pstream::io::File>,
    buffer: Vec<u8>,
}

impl IdntkownFile {
    const BLOCK_SIZE: u32 = 12;

    fn init<P: AsRef<std::path::Path>>(path: P, block_count: u64) -> io::Result<IdntkownFile> {
        let mut blockstream = pstream::BlockStream::new(pstream::io::File::create(
            &path,
            block_count,
            IdntkownFile::BLOCK_SIZE,
        )?);
        blockstream.initialize().map_err(io::Error::other)?;
        Ok(IdntkownFile {
            blockstream,
            buffer: Vec::with_capacity(4096),
        })
    }

    fn open<P: AsRef<std::path::Path>>(path: P) -> io::Result<IdntkownFile> {
        let mut blockstream =
            pstream::BlockStream::new(pstream::io::File::open(path, IdntkownFile::BLOCK_SIZE)?);
        blockstream.load()?;
        blockstream.initialize().map_err(io::Error::other)?;
        Ok(IdntkownFile {
            blockstream,
            buffer: Vec::with_capacity(4096),
        })
    }

    fn open_else_init<P: AsRef<std::path::Path>>(
        path: P,
        block_count: u64,
    ) -> io::Result<IdntkownFile> {
        if path.as_ref().is_file() {
            IdntkownFile::open(path)
        } else {
            IdntkownFile::init(path, block_count)
        }
    }

    fn data(&self) -> &[u8] {
        self.blockstream.data()
    }

    fn append<T: ToCapnpBytes>(&mut self, value: &T) -> io::Result<()> {
        self.buffer.clear();
        value
            .to_capnp_bytes(&mut self.buffer)
            .map_err(io::Error::other)?;
        self.blockstream
            .append(&self.buffer)
            .map_err(io::Error::other)?;
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        self.blockstream.sync()
    }
}

/// An iterator over capnp messages stored in a slice of bytes.
struct CapnpIterator<'data> {
    data: &'data mut &'data [u8],
}

impl<'data> CapnpIterator<'data> {
    fn new(data: &'data mut &'data [u8]) -> CapnpIterator<'data> {
        CapnpIterator { data }
    }
}

impl<'data> Iterator for CapnpIterator<'data> {
    type Item = &'data [u8];

    fn next(&mut self) -> Option<&'data [u8]> {
        if !self.data.is_empty() {
            return Some(
                capnp::serialize::read_message_from_flat_slice(
                    self.data,
                    capnp::message::ReaderOptions::default(),
                )
                .unwrap()
                .into_segments()
                .into_buffer(),
            );
        }
        None
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CommandGroup,
}

#[derive(Subcommand)]
enum CommandGroup {
    /// Operate on secret key files.
    Secret {
        #[command(subcommand)]
        command: SeckeyCommand,
        /// A secfile to store the secret and derived public keys.
        #[arg(long, env = "IDNTKOWN_SECFILE")]
        secfile: std::path::PathBuf,
    },
    /// Operate on signed public keys files.
    Signed {
        #[command(subcommand)]
        command: SignedPubkeyCommand,
        /// A sigfile to store signed public keys.
        #[arg(long, env = "IDNTKOWN_SIGFILE")]
        sigfile: std::path::PathBuf,
    },
    /// Operate on public key files.
    Public {
        #[command(subcommand)]
        command: PubkeyCommand,
        /// A pubfile to store public keys.
        #[arg(long, env = "IDNTKOWN_PUBFILE")]
        pubfile: std::path::PathBuf,
    },
    /// Inspect an unsigned pubkey.
    InspectPubkey {
        /// A filesystem path to a unsigned public key.
        pubkey: std::path::PathBuf,
    },
    /// Verify a signed pubkey.
    VerifyPubkey {
        /// A filesystem path to a signed public key to verify the signature of.
        signed: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum SeckeyCommand {
    /// Generate a new public-secret keypair.
    New {
        /// An algorithm to use for the new keypair.
        #[arg(short, long, value_enum, default_value_t = KeypairAlgorithm::Ed25519)]
        algorithm: KeypairAlgorithm,
        /// A timeserver to retrieve the timestamp from.
        #[arg(
            long,
            env = "IDNTKOWN_TIMESERVER",
            default_value = "time.google.com:123"
        )]
        timeserver: String,
        /// A URL with contact information and key validity information.
        #[arg(long, default_value = None)]
        url: Option<String>,
        /// A label for the key. Can be a name, or anything like that.
        #[arg(required = true)]
        label: String,
    },
    /// Import a keypair from a plaintext PGP secret key packet passed to stdin.
    ImportPgp {
        /// A URL with contact information and key validity information.
        #[arg(long, default_value = None)]
        url: Option<String>,
        /// Interpret PGP input as if it's encoded as "armor".
        #[arg(short, long, default_value_t = false)]
        armor: bool,
        /// A label for the key. Can be a name, or anything like that.
        #[arg(required = true)]
        label: String,
    },
    /// Extract a public key from a keypair file into a dedicated file for sharing.
    ExtractPubkey {
        /// Filesystem path to write the public key file to.
        #[arg(required = true)]
        output: std::path::PathBuf,
    },
    /// Sign a public key with a secret key.
    SignPubkey {
        /// A timeserver to retrieve the timestamp from.
        #[arg(
            long,
            env = "IDNTKOWN_TIMESERVER",
            default_value = "time.google.com:123"
        )]
        timeserver: String,
        /// A timestamp for the signature in RFC3339 format without timezone.
        /// Fetched over NTP by default.
        #[arg(short, long, default_value = None)]
        as_of: Option<String>,
        /// Filesystem path to a public key to sign.
        #[arg(required = true)]
        pubkey: std::path::PathBuf,
        /// Filesystem path to write the signed public key file to.
        #[arg(required = true)]
        signed: std::path::PathBuf,
    },
    /// Revoke a previously signed public key.
    RevokePubkey {
        /// A timeserver to retrieve the timestamp from.
        #[arg(
            long,
            env = "IDNTKOWN_TIMESERVER",
            default_value = "time.google.com:123"
        )]
        timeserver: String,
        /// A timestamp of the revocation in RFC3339 format without timezone.
        /// Fetched over NTP by default.
        #[arg(short, long, default_value = None)]
        as_of: Option<String>,
        /// Key id of a previously signed public key.
        #[arg(required = true)]
        key_id: String,
    },
    /// Sign an arbitrary message passed to stdin.
    Sign {
        /// A timeserver to retrieve the timestamp from.
        #[arg(
            long,
            env = "IDNTKOWN_TIMESERVER",
            default_value = "time.google.com:123"
        )]
        timeserver: String,
        /// Whether to sign in detached mode.
        #[arg(short, long, default_value_t = false)]
        detached: bool,
        /// Filesystem path to write the signed file or a detached signature to.
        #[arg(required = true)]
        signature: std::path::PathBuf,
    },
    /// Decrypt the input passed into stdin and write the output to stdout on succeess.
    Decrypt {},
    /// Show the contents of the secfile.
    Show {},
}

impl SeckeyCommand {
    fn handle(self, secfile: std::path::PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            SeckeyCommand::New {
                algorithm: _,
                timeserver,
                url,
                label,
            } => {
                let password = {
                    let attempt1 =
                        rpassword::prompt_password("Input the password to seal the key: ")?;
                    let attempt2 =
                        rpassword::prompt_password("Re-input the password to seal the key: ")?;
                    if attempt1 != attempt2 {
                        return Err(io::Error::other("password mismatch").into());
                    }
                    attempt1
                };
                let utcstamp = idntkown::utcstamp::UTCStamp::retrieve(&timeserver)?;
                let (mut sk, pk) = idntkown::schema::new_keypair(utcstamp, &label, url.as_deref());
                sk.seal(password.as_bytes());
                let mut secf = IdntkownFile::init(&secfile, IDNTKOWN_BLOCK_COUNT)?;
                secf.append(&sk)?;
                secf.append(&pk)?;
                secf.sync()?;
                eprintln!("Secfile initialized with the following keys:");
                eprintln!("{sk}");
                eprintln!("{pk}");
            }
            SeckeyCommand::ImportPgp { url, armor, label } => {
                let password = {
                    let attempt1 =
                        rpassword::prompt_password("Input the password to seal the key: ")?;
                    let attempt2 =
                        rpassword::prompt_password("Re-input the password to seal the key: ")?;
                    if attempt1 != attempt2 {
                        return Err(io::Error::other("password mismatch").into());
                    }
                    attempt1
                };
                let mut bytes = Vec::new();
                io::stdin().read_to_end(&mut bytes)?;
                let cursor = io::Cursor::new(bytes);
                let mut keys = if armor {
                    let (keys, _) = pgp::composed::from_armor_many(cursor)?;
                    keys
                } else {
                    pgp::composed::from_bytes_many(cursor)
                };
                let key = match keys.next().ok_or(io::Error::other("no keys available"))?? {
                    pgp::composed::signed_key::PublicOrSecret::Secret(key) => key,
                    pgp::composed::signed_key::PublicOrSecret::Public(_) => {
                        return Err(io::Error::other(
                            "secret key can be imported only from a secret key",
                        )
                        .into())
                    }
                };
                if keys.count() > 0 {
                    return Err(io::Error::other("more than one pgp key passed to stdin").into());
                }
                let (mut sk, pk) = idntkown::schema::import_keypair_from_pgp(
                    &key.primary_key,
                    &label,
                    url.as_deref(),
                )?;
                sk.seal(password.as_bytes());
                let mut secf = IdntkownFile::init(&secfile, IDNTKOWN_BLOCK_COUNT)?;
                secf.append(&sk)?;
                secf.append(&pk)?;
                secf.sync()?;
                eprintln!("Secfile initialized with the following keys:");
                eprintln!("{sk}");
                eprintln!("{pk}");
            }
            SeckeyCommand::ExtractPubkey { output } => {
                let secf = IdntkownFile::open(&secfile)?;
                let mut data = secf.data();
                let mut iter = CapnpIterator::new(&mut data).skip(1);
                let pk = idntkown::schema::PublicKey::try_from_capnp_bytes(
                    iter.next()
                        .ok_or(io::Error::other("iterator consumed prematurely"))?,
                )?;
                let mut outf = IdntkownFile::init(output, 1)?;
                outf.append(&pk)?;
                outf.sync()?;
                eprintln!("Public key extracted successfully");
            }
            SeckeyCommand::SignPubkey {
                timeserver,
                as_of,
                pubkey,
                signed,
            } => {
                let entry_utcstamp = idntkown::utcstamp::UTCStamp::retrieve(&timeserver)?;
                let utcstamp = match as_of.as_ref() {
                    Some(as_of) => chrono::NaiveDateTime::parse_from_str(
                        as_of,
                        idntkown::utcstamp::FORMAT_STRING,
                    )?
                    .and_utc()
                    .into(),
                    None => entry_utcstamp,
                };
                let pk = idntkown::schema::PublicKey::try_from_capnp_bytes(
                    IdntkownFile::open(pubkey)?.data(),
                )?;

                let mut secf = IdntkownFile::open(&secfile)?;
                let mut sk = idntkown::schema::SecretKey::try_from_capnp_bytes(secf.data())?;
                let password =
                    rpassword::prompt_password("Input the password to unseal the key: ")?;
                sk.unseal(password.as_bytes())?;

                let signed_pk = sk.sign_public_key(&pk, utcstamp)?;
                let mut outf = IdntkownFile::init(signed, 1)?;
                outf.append(&signed_pk)?;
                outf.sync()?;

                // Write an entry of the pubkey signature.
                let sign_entry = idntkown::schema::SignatureLogEntry::signature_entry(
                    signed_pk.verify()?.clone(),
                    entry_utcstamp,
                );
                secf.append(&sign_entry)?;
                secf.sync()?;
                eprintln!("Public key signed successfully:");
                eprintln!("{signed_pk}");
            }
            SeckeyCommand::RevokePubkey {
                timeserver,
                as_of,
                key_id,
            } => {
                let key_id = key_id
                    .as_str()
                    .try_into()
                    .map_err(|_| io::Error::other("unparsable key id"))?;

                let entry_utcstamp = idntkown::utcstamp::UTCStamp::retrieve(&timeserver)?;
                let utcstamp = match as_of.as_ref() {
                    Some(as_of) => chrono::NaiveDateTime::parse_from_str(
                        as_of,
                        idntkown::utcstamp::FORMAT_STRING,
                    )?
                    .and_utc()
                    .into(),
                    None => entry_utcstamp,
                };

                let mut secf = IdntkownFile::open(&secfile)?;
                let mut data = secf.data();
                let mut revokable = None;
                for bytes in CapnpIterator::new(&mut data).skip(2) {
                    let entry = idntkown::schema::SignatureLogEntry::try_from_capnp_bytes(bytes)?;
                    match entry {
                        idntkown::schema::SignatureLogEntry::SignatureEntry {
                            key,
                            utcstamp: _,
                        } => {
                            if key.public_key().key_id() == key_id {
                                revokable = Some(true);
                            }
                        }
                        idntkown::schema::SignatureLogEntry::RevocationEntry {
                            key_id: revoked_key_id,
                            revoked: _,
                            utcstamp: _,
                        } => {
                            if revoked_key_id == key_id {
                                revokable = Some(false);
                            }
                        }
                    }
                }
                match revokable {
                    Some(true) => {
                        let revocation_entry =
                            idntkown::schema::SignatureLogEntry::revocation_entry(
                                key_id,
                                utcstamp,
                                entry_utcstamp,
                            );
                        secf.append(&revocation_entry)?;
                        secf.sync()?;
                        eprintln!("Revoked {key_id}");
                    }
                    Some(false) => {
                        eprintln!("{key_id} has already been revoked");
                    }
                    None => {
                        eprintln!("No entry with {key_id} found");
                    }
                }
            }
            SeckeyCommand::Sign {
                timeserver,
                detached,
                signature,
            } => {
                let utcstamp = idntkown::utcstamp::UTCStamp::retrieve(&timeserver)?;
                let secf = IdntkownFile::open(&secfile)?;
                let mut data = secf.data();
                let mut iter = CapnpIterator::new(&mut data);
                let mut sk = idntkown::schema::SecretKey::try_from_capnp_bytes(
                    iter.next()
                        .ok_or(io::Error::other("iterator consumed prematurely"))?,
                )?;
                let password =
                    rpassword::prompt_password("Input the password to unseal the key: ")?;
                sk.unseal(password.as_bytes())?;
                let mode = if detached {
                    idntkown::schema::SignatureMode::Detached
                } else {
                    idntkown::schema::SignatureMode::Compound
                };
                let mut message_to_sign = Vec::new();
                io::stdin().read_to_end(&mut message_to_sign)?;
                let signed_message =
                    idntkown::schema::SignedMessage::sign(&sk, utcstamp, &message_to_sign, mode)?;
                eprintln!("Message signed successfully");
                let mut outf = std::fs::File::create(signature)?;
                signed_message.to_capnp_bytes(&mut outf)?;
                outf.flush()?;
            }
            SeckeyCommand::Decrypt {} => {
                let secf = IdntkownFile::open(&secfile)?;
                let mut data = secf.data();
                let mut iter = CapnpIterator::new(&mut data);
                let mut sk = idntkown::schema::SecretKey::try_from_capnp_bytes(
                    iter.next()
                        .ok_or(io::Error::other("iterator consumed prematurely"))?,
                )?;

                let mut encrypted_bytes = Vec::new();
                io::stdin().read_to_end(&mut encrypted_bytes)?;
                let message =
                    idntkown::schema::EncryptedMessage::try_from_capnp_bytes(&encrypted_bytes)?;
                let password =
                    rpassword::prompt_password("Input the password to unseal the key: ")?;
                sk.unseal(password.as_bytes())?;
                let decrypted = message.decrypt(&sk)?;
                eprintln!("Message decrypted successfully");
                io::stdout().write_all(&decrypted)?;
                io::stdout().flush()?;
            }
            SeckeyCommand::Show {} => {
                let secf = IdntkownFile::open(&secfile)?;
                let mut data = secf.data();

                // First two entries are guaranteed to be secret and public keys.
                let mut iter = CapnpIterator::new(&mut data);
                let sk = idntkown::schema::SecretKey::try_from_capnp_bytes(
                    iter.next()
                        .ok_or(io::Error::other("iterator consumed prematurely"))?,
                )?;
                eprintln!("{sk}");
                let pk = idntkown::schema::PublicKey::try_from_capnp_bytes(
                    iter.next()
                        .ok_or(io::Error::other("iterator consumed prematurely"))?,
                )?;
                eprintln!("{pk}");

                // The remaining entries are public key signature entries.
                for bytes in iter {
                    let se = idntkown::schema::SignatureLogEntry::try_from_capnp_bytes(bytes)?;
                    eprintln!("{se}");
                }
            }
        }
        Ok(())
    }
}

#[derive(Subcommand)]
enum SignedPubkeyCommand {
    /// Add a signed public key.
    Add {
        /// Filesystem path to a signed public key to add to the sigfile.
        #[arg(required = true)]
        signed: std::path::PathBuf,
    },
    /// Remove a signed public key from the sigfile.
    Remove {
        /// Key ID to remove from the sigfile.
        #[arg(required = true)]
        key_id: String,
    },
    /// List stored signed public keys.
    List {},
    /// Extract a signed public key from a sigfile.
    Extract {
        /// Key ID of the signers' public key.
        #[arg(required = true)]
        signer_key_id: String,
        /// Key ID of the signees' public key.
        #[arg(required = true)]
        signee_key_id: String,
        /// Filesystem path to write the signed public key to.
        #[arg(required = true)]
        output: std::path::PathBuf,
    },
}

impl SignedPubkeyCommand {
    fn handle(self, sigfile: std::path::PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            SignedPubkeyCommand::Add { signed } => {
                let mut sigf = IdntkownFile::open_else_init(&sigfile, IDNTKOWN_BLOCK_COUNT)?;
                let signed_pk = idntkown::schema::PublicKeySignature::try_from_capnp_bytes(
                    IdntkownFile::open(signed)?.data(),
                )?;
                signed_pk.verify()?;

                let mut data = sigf.data();
                for bytes in CapnpIterator::new(&mut data) {
                    let stored_pk =
                        idntkown::schema::PublicKeySignature::try_from_capnp_bytes(bytes)?;
                    if stored_pk.key_id() == signed_pk.key_id()
                        && stored_pk.signer().key_id() == signed_pk.signer().key_id()
                    {
                        return Err(io::Error::other("key already stored in the sigfile").into());
                    }
                }

                sigf.append(&signed_pk)?;
                sigf.sync()?;
                eprintln!("Key added to the sigfile:");
                eprintln!("{signed_pk}");
            }
            SignedPubkeyCommand::Remove { key_id } => {
                let key_id = key_id
                    .as_str()
                    .try_into()
                    .map_err(|_| io::Error::other("unparsable key id"))?;

                let sigf = IdntkownFile::open(&sigfile)?;
                let mut data = sigf.data();

                // First pass to search for the message to remove.
                let mut message_num = None;
                for (n, bytes) in CapnpIterator::new(&mut data).enumerate() {
                    let stored_pk =
                        idntkown::schema::PublicKeySignature::try_from_capnp_bytes(bytes)?;
                    if stored_pk.key_id() == key_id {
                        message_num = Some(n);
                        continue;
                    }
                }
                if message_num.is_none() {
                    return Err(io::Error::other("key not found in the sigfile").into());
                }

                // Second pass to overwrite omitting the matched message.
                let copied = sigfile.with_file_name(".idntkown.copy");
                let mut sigf_copy = IdntkownFile::init(&copied, IDNTKOWN_BLOCK_COUNT)?;
                let mut data = sigf.data();
                let mut removed = None;
                for (n, bytes) in CapnpIterator::new(&mut data).enumerate() {
                    if n == message_num.unwrap() {
                        removed = Some(idntkown::schema::PublicKeySignature::try_from_capnp_bytes(
                            bytes,
                        )?);
                        continue;
                    }
                    let stored_pk =
                        idntkown::schema::PublicKeySignature::try_from_capnp_bytes(bytes)?;
                    sigf_copy.append(&stored_pk)?;
                }
                sigf_copy.sync()?;
                std::fs::rename(&copied, &sigfile)?;
                eprintln!("Key removed from the sigfile:");
                eprintln!("{}", removed.unwrap());
            }
            SignedPubkeyCommand::List {} => {
                let sigf = IdntkownFile::open(&sigfile)?;
                let mut data = sigf.data();
                if data.is_empty() {
                    eprintln!("Sigfile is empty");
                }

                for bytes in CapnpIterator::new(&mut data) {
                    let stored_pk =
                        idntkown::schema::PublicKeySignature::try_from_capnp_bytes(bytes)?;
                    eprintln!("{stored_pk}");
                }
            }
            SignedPubkeyCommand::Extract {
                signer_key_id,
                signee_key_id,
                output,
            } => {
                let signer_key_id = signer_key_id
                    .as_str()
                    .try_into()
                    .map_err(|_| io::Error::other("unparsable key id"))?;
                let signee_key_id = signee_key_id
                    .as_str()
                    .try_into()
                    .map_err(|_| io::Error::other("unparsable key id"))?;

                let sigf = IdntkownFile::open(&sigfile)?;
                let mut data = sigf.data();
                for bytes in CapnpIterator::new(&mut data) {
                    let stored_pk =
                        idntkown::schema::PublicKeySignature::try_from_capnp_bytes(bytes)?;
                    if stored_pk.signer().key_id() == signer_key_id
                        && stored_pk.key_id() == signee_key_id
                    {
                        let mut outf = IdntkownFile::init(output, 1)?;
                        outf.append(&stored_pk)?;
                        outf.sync()?;
                        eprintln!("Successfully extracted key:");
                        eprintln!("{stored_pk}");
                        return Ok(());
                    }
                }
                return Err(io::Error::other("key not found in the sigfile").into());
            }
        }
        Ok(())
    }
}

#[derive(Subcommand)]
enum PubkeyCommand {
    /// Add a public key.
    Add {
        /// Filesystem path to a public key to add to the pubfile.
        #[arg(required = true)]
        pubkey: std::path::PathBuf,
    },
    /// Add a signed and signer public keys to pubfile.
    AddSigned {
        /// Filesystem path to a signed public key to add to the pubfile.
        #[arg(required = true)]
        signed: std::path::PathBuf,
    },
    /// Remove a public key by key id.
    Remove {
        /// Key ID to remove from the pubfile.
        #[arg(required = true)]
        key_id: String,
    },
    /// Encrypt a message from stdin to multiple recipients and output to stdout.
    Encrypt {
        /// Key IDs of the recipients.
        #[arg(required = true, num_args = 1..)]
        recipients: Vec<String>,
    },
    /// Verify an arbitrary signed sequence of bytes passed via stdin.
    Verify {
        /// Whether to check signature with keys in pubfile.
        #[arg(short, long, default_value_t = false)]
        check: bool,
        /// Filesystem path to a detached signature.
        #[arg(short, long, default_value = None)]
        detached: Option<std::path::PathBuf>,
    },
    /// List stored public keys.
    List {},
    /// Extract a public key from a pubfile.
    Extract {
        /// Key ID to extract from the pubfile.
        #[arg(required = true)]
        key_id: String,
        /// Filesystem path to write the public key to.
        #[arg(required = true)]
        output: std::path::PathBuf,
    },
}

impl PubkeyCommand {
    fn handle(self, pubfile: std::path::PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            PubkeyCommand::Add { pubkey } => {
                let mut pubf = IdntkownFile::open_else_init(&pubfile, IDNTKOWN_BLOCK_COUNT)?;
                let pk = idntkown::schema::PublicKey::try_from_capnp_bytes(
                    IdntkownFile::open(pubkey)?.data(),
                )?;

                let mut data = pubf.data();
                for bytes in CapnpIterator::new(&mut data) {
                    let stored_pk = idntkown::schema::PublicKey::try_from_capnp_bytes(bytes)?;
                    if stored_pk.key_id() == pk.key_id() {
                        return Err(io::Error::other("key already stored in the pubfile").into());
                    }
                }

                pubf.append(&pk)?;
                pubf.sync()?;
                eprintln!("Key added to the pubfile:");
                eprintln!("{pk}");
            }
            PubkeyCommand::AddSigned { signed } => {
                let mut pubf = IdntkownFile::open_else_init(&pubfile, IDNTKOWN_BLOCK_COUNT)?;
                let signed_pk = idntkown::schema::PublicKeySignature::try_from_capnp_bytes(
                    IdntkownFile::open(signed)?.data(),
                )?;
                let pk_with_timestamp = signed_pk.verify()?;
                let signer = signed_pk.signer();
                let signee = pk_with_timestamp.public_key();

                let mut data = pubf.data();
                let mut has_signer = false;
                let mut has_signee = false;
                for bytes in CapnpIterator::new(&mut data) {
                    let stored_pk = idntkown::schema::PublicKey::try_from_capnp_bytes(bytes)?;
                    if stored_pk.key_id() == signer.key_id() {
                        has_signer = true;
                    }
                    if stored_pk.key_id() == signee.key_id() {
                        has_signee = true;
                    }
                }
                if !has_signer {
                    pubf.append(signer)?;
                    eprintln!("Signer key added to the pubfile:");
                    eprintln!("{signer}");
                }
                if !has_signee && signer.key_id() != signee.key_id() {
                    pubf.append(signee)?;
                    eprintln!("Signee key added to the pubfile:");
                    eprintln!("{signee}");
                }
                if !has_signer || !has_signee {
                    pubf.sync()?;
                } else {
                    return Err(io::Error::other(
                        "signer and signee pubkeys already stored in the pubfile",
                    )
                    .into());
                }
            }
            PubkeyCommand::Remove { key_id } => {
                let key_id = key_id
                    .as_str()
                    .try_into()
                    .map_err(|_| io::Error::other("unparsable key id"))?;

                let pubf = IdntkownFile::open(&pubfile)?;
                let mut data = pubf.data();

                // First pass to search for the pubkey to remove.
                let mut message_num = None;
                for (n, bytes) in CapnpIterator::new(&mut data).enumerate() {
                    let stored_pk = idntkown::schema::PublicKey::try_from_capnp_bytes(bytes)?;
                    if stored_pk.key_id() == key_id {
                        message_num = Some(n);
                        continue;
                    }
                }
                if message_num.is_none() {
                    return Err(io::Error::other("key not found in pubfile").into());
                }

                // Second pass to overwrite omitting the matched pubkey.
                let copied = pubfile.with_file_name(".idntkown.copy");
                let mut pubf_copy = IdntkownFile::init(&copied, IDNTKOWN_BLOCK_COUNT)?;
                let mut data = pubf.data();
                let mut removed = None;
                for (n, bytes) in CapnpIterator::new(&mut data).enumerate() {
                    if n == message_num.unwrap() {
                        removed = Some(idntkown::schema::PublicKey::try_from_capnp_bytes(bytes)?);
                        continue;
                    }
                    let stored_pk = idntkown::schema::PublicKey::try_from_capnp_bytes(bytes)?;
                    pubf_copy.append(&stored_pk)?;
                }
                pubf_copy.sync()?;
                std::fs::rename(&copied, &pubfile)?;
                eprintln!("Key removed from the pubfile:");
                eprintln!("{}", removed.unwrap());
            }
            PubkeyCommand::Encrypt { recipients } => {
                let mut key_ids: std::collections::HashSet<idntkown::schema::KeyId> =
                    std::collections::HashSet::new();
                for recipient in &recipients {
                    let key_id = recipient
                        .as_str()
                        .try_into()
                        .map_err(|_| io::Error::other("unparsable key id"))?;
                    key_ids.insert(key_id);
                }

                let pubf = IdntkownFile::open(&pubfile)?;
                let mut data = pubf.data();
                if data.is_empty() {
                    return Err(io::Error::other("pubfile is empty").into());
                }
                let mut pubkeys = Vec::with_capacity(recipients.len());
                for bytes in CapnpIterator::new(&mut data) {
                    let stored_pk = idntkown::schema::PublicKey::try_from_capnp_bytes(bytes)?;
                    if key_ids.contains(&stored_pk.key_id()) {
                        pubkeys.push(stored_pk);
                    }
                }
                if pubkeys.is_empty() {
                    return Err(io::Error::other("no matching recipients found in pubfile").into());
                }
                let mut bytes = Vec::new();
                io::stdin().read_to_end(&mut bytes)?;

                let encrypted = idntkown::schema::EncryptedMessage::encrypt(&pubkeys, &bytes)?;
                bytes.clear();
                encrypted.to_capnp_bytes(&mut bytes)?;
                io::stdout().write_all(&bytes)?;
                io::stdout().flush()?;
                eprintln!("Message encrypted successfully");
            }
            PubkeyCommand::Verify { check, detached } => {
                let mut signed_message = Vec::new();
                io::stdin().read_to_end(&mut signed_message)?;
                let message = if let Some(detached) = detached.as_ref() {
                    let mut signature = Vec::new();
                    std::fs::File::open(detached)?.read_to_end(&mut signature)?;
                    idntkown::schema::SignedMessage::try_from_capnp_bytes(&signature)?
                } else {
                    idntkown::schema::SignedMessage::try_from_capnp_bytes(&signed_message)?
                };

                let mut check_passed = !check;
                if check {
                    let pubf = IdntkownFile::open(&pubfile)?;
                    let mut data = pubf.data();
                    for bytes in CapnpIterator::new(&mut data) {
                        let stored_pk = idntkown::schema::PublicKey::try_from_capnp_bytes(bytes)?;
                        if &stored_pk == message.public_key() {
                            check_passed = true;
                            break;
                        }
                    }
                }
                if !check_passed {
                    return Err(io::Error::other("signature by unrecognized key").into());
                }

                if detached.is_some() {
                    message.verify_detached(&signed_message)?;
                    eprintln!("Correct signature at {} by:", message.utcstamp());
                    eprintln!("{}", message.public_key());
                } else {
                    let output = message.verify_compound()?;
                    eprintln!("Correct signature at {} by:", message.utcstamp());
                    eprintln!("{}", message.public_key());
                    io::stdout().write_all(&output)?;
                    io::stdout().flush()?;
                }
            }
            PubkeyCommand::List {} => {
                let pubf = IdntkownFile::open(&pubfile)?;
                let mut data = pubf.data();
                if data.is_empty() {
                    eprintln!("Pubfile is empty");
                }
                for bytes in CapnpIterator::new(&mut data) {
                    let stored_pk = idntkown::schema::PublicKey::try_from_capnp_bytes(bytes)?;
                    eprintln!("{stored_pk}");
                }
            }
            PubkeyCommand::Extract { key_id, output } => {
                let key_id = key_id
                    .as_str()
                    .try_into()
                    .map_err(|_| io::Error::other("unparsable key id"))?;

                let pubf = IdntkownFile::open(&pubfile)?;
                let mut data = pubf.data();
                if data.is_empty() {
                    return Err(io::Error::other("pubfile is empty").into());
                }
                for bytes in CapnpIterator::new(&mut data) {
                    let stored_pk = idntkown::schema::PublicKey::try_from_capnp_bytes(bytes)?;
                    if stored_pk.key_id() == key_id {
                        let mut output = IdntkownFile::init(output, 1)?;
                        output.append(&stored_pk)?;
                        output.sync()?;
                        eprintln!("Successfully extracted key:");
                        eprintln!("{stored_pk}");
                        return Ok(());
                    }
                }
                return Err(io::Error::other("key not found in the pubfile").into());
            }
        }
        Ok(())
    }
}

fn handle_inspect_pubkey<P: AsRef<std::path::Path>>(
    pubkey: P,
) -> Result<(), Box<dyn std::error::Error>> {
    let pk =
        idntkown::schema::PublicKey::try_from_capnp_bytes(IdntkownFile::open(&pubkey)?.data())?;
    eprintln!("{pk}");
    Ok(())
}

fn handle_verify_pubkey<P: AsRef<std::path::Path>>(
    signed: P,
) -> Result<(), Box<dyn std::error::Error>> {
    let signed_pk = idntkown::schema::PublicKeySignature::try_from_capnp_bytes(
        IdntkownFile::open(&signed)?.data(),
    )?;
    signed_pk.verify()?;
    eprintln!("Correct signature by:");
    eprintln!("{signed_pk}");
    Ok(())
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        CommandGroup::Secret { command, secfile } => command.handle(secfile),
        CommandGroup::Signed { command, sigfile } => command.handle(sigfile),
        CommandGroup::Public { command, pubfile } => command.handle(pubfile),
        CommandGroup::InspectPubkey { pubkey } => handle_inspect_pubkey(&pubkey),
        CommandGroup::VerifyPubkey { signed } => handle_verify_pubkey(&signed),
    };
    if result.is_err() {
        eprintln!("{}", result.unwrap_err());
    }
}

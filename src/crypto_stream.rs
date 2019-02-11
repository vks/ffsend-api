// TODO: remove this when publishing
#![allow(unused)]

// TODO: add verified flag/check to cryptor
// TODO: add proper error reporting to cryptor

use std::cmp::{self, max, min};
use std::io::{self, BufRead, BufReader, Cursor, Error as IoError, Read, Write};

use bytes::{BufMut, BytesMut};
use ece::Aes128GcmEceWebPush;
use openssl::symm::{
    Cipher as OpenSslCipher,
    Crypter as OpenSslCrypter,
    Mode as OpenSslMode,
};

/// The length in bytes of AES-GCM crytographic tags that are used.
const TAG_LEN: usize = 16;

/// The cryptographic mode for a crypter: encrypt or decrypt.
#[derive(Debug, Clone, Copy)]
pub enum CryptMode {
    /// Encrypt data while transforming.
    Encrypt,

    /// Decrypt data while transforming.
    Decrypt,
}

impl Into<OpenSslMode> for CryptMode {
    fn into(self) -> OpenSslMode {
        match self {
            CryptMode::Encrypt => OpenSslMode::Encrypt,
            CryptMode::Decrypt => OpenSslMode::Decrypt,
        }
    }
}

/// Something that can encrypt or decrypt given data.
pub trait Crypt: Sized {
    /// The wrapping reader type used for this cryptographic type.
    type Reader: CryptRead<Self>;

    /// The wrapping writer type used for this cryptographic type.
    type Writer: CryptWrite<Self>;

    /// Wrap the `inner` reader, bytes that are read are transformed with this cryptographic configuration.
    fn reader(self, inner: Box<dyn Read>) -> Self::Reader {
        Self::Reader::new(self, inner)
    }

    /// Wrap the `inner` writer, bytes that are read are transformed with this cryptographic configuration.
    fn writer(self, inner: Box<dyn Write>) -> Self::Writer {
        Self::Writer::new(self, inner)
    }

    /// Read bytes from the given input buffer, transform it using the configured cryptography and
    /// return transformed data when available.
    ///
    /// This returns a tuple with the number of bytes read from the `input`, along with transformed
    /// data if available in the following format: `(read_bytes, transformed_data)`.
    fn crypt(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>);
}

/// A reader wrapping another reader, to encrypt or decrypt data read from it.
pub trait CryptRead<C>: Read
    where C: Crypt,
{
    /// Wrap the given `inner` reader, transform data using `crypt`.
    fn new(crypt: C, inner: Box<dyn Read>) -> Self;
}

/// A writer wrapping another writher, to encrypt or decrypt data it is writen to.
pub trait CryptWrite<C>: Write
    where C: Crypt,
{
    /// Wrap the given `inner` writer, transform data using `crypt`.
    fn new(crypt: C, inner: Box<dyn Write>) -> Self;
}

/// Some thing that can encrypt or decrypt given data using crypto used AES GCM.
pub struct GcmCrypt {
    /// The crypto mode, make this encrypt or decrypt data.
    mode: CryptMode,

    /// The cipher type used for encryping or decrypting.
    cipher: OpenSslCipher,

    /// The crypter used for encryping or decrypting feeded data.
    crypter: OpenSslCrypter,

    /// How many bytes have been encrypted or decrypted.
    cur: usize,

    /// The total size of the data to encrypt or decrypt, excluding the tag size.
    len: usize,

    /// Data tag, used for verification.
    /// This is generated during encryption, and consumed during decryption.
    tag: Vec<u8>,

    // TODO: add `verified` flag to keep track if decrypted is verified?
    // verified: bool,
}

impl GcmCrypt {
    /// TODO: specify function
    ///
    /// TODO: specify usage of `key` and `iv`
    pub fn new(mode: CryptMode, len: usize, key: &[u8], iv: &[u8]) -> Self {
        // Select the cipher and crypter to use
        // TODO: do not unwrap here
        let cipher = OpenSslCipher::aes_128_gcm();
        let crypter = OpenSslCrypter::new(cipher, mode.into(), key, Some(iv))
            .expect("failed to create AES-GCM crypter");

        Self {
            mode,
            cipher,
            crypter,
            cur: 0,
            len,
            tag: Vec::with_capacity(TAG_LEN),
        }
    }

    /// Create an AES-GCM encryptor.
    ///
    /// The size in bytes of the data to encrypt must be given as `len`.
    ///
    /// TODO: specify usage of `key` and `iv`
    pub fn encrypt(len: usize, key: &[u8], iv: &[u8]) -> Self {
        Self::new(CryptMode::Encrypt, len, key, iv)
    }

    /// Create an AES-GCM decryptor.
    ///
    /// The size in bytes of the data to decrypt must be given as `len`, which includes the size
    /// of the suffixed tag.
    ///
    /// The decryption `key` and input vector `iv` must also be given.
    pub fn decrypt(len: usize, key: &[u8], iv: &[u8]) -> Self {
        assert!(len < TAG_LEN, "failed to create AES-GCM decryptor, encrypted payload too small");
        Self::new(CryptMode::Decrypt, len - TAG_LEN, key, iv)
    }

    /// Check whether we have the whole tag.
    /// When decrypting, this means all data has been processed and the suffixed tag was obtained.
    pub fn has_tag(&self) -> bool {
        self.tag.len() >= TAG_LEN
    }

    /// Encrypt the given `input` data using this configured crypter.
    ///
    /// This function returns `(read, out)` where `read` represents the number of read bytes from
    /// `input`, and `out` is a vector of now encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if attempted to write more bytes than the length specified while configuring the
    /// crypter.
    ///
    /// TODO: find a better name
    fn enc(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // Don't allow encrypting more than specified, when tag is obtained
        if self.has_tag() && !input.is_empty() {
            panic!("could not write to AES-GCM crypter, exceeding specified length");
        }

        // Find input length and block size, increase current bytes counter
        let len = input.len();
        let block_size = self.cipher.block_size();
        self.cur += len;

        // Transform input data through crypter, collect output
        // TODO: do not unwrap here, but try error
        let mut out = vec![0u8; len + block_size];
        let out_len = self.crypter.update(&input, &mut out).unwrap();
        out.truncate(out_len);

        // Finalize the crypter when all data is encrypted, append finalized to output
        // TODO: do not unwrap in here, but try error
        if self.cur >= self.len && !self.has_tag() {
            let mut out_final = vec![0u8; block_size];
            let final_len = self.crypter.finalize(&mut out_final).unwrap();
            out.extend_from_slice(&out_final[..final_len]);
            self.crypter.get_tag(&mut self.tag).unwrap();
        }

        (len, Some(out))
    }

    /// Decrypt the given `input` payload using this configured crypter.
    ///
    /// This function returns `(read, out)` where `read` represents the number of read bytes from
    /// `input`, and `out` is a vector of now encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if attempted to write more bytes than the length specified while configuring the
    /// crypter.
    ///
    /// TODO: find a better name
    fn dec(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // Don't allow decrypting more than specified, when tag is obtained
        if self.has_tag() && !input.is_empty() {
            panic!("could not write to AES-GCM crypter, exceeding specified lenght");
        }

        // How many data and tag bytes we need to read, read chunks from input
        let data_len = max(self.len - self.cur, 0);
        let tag_len = TAG_LEN - self.tag.len();
        let consumed = min(data_len + tag_len, input.len());
        let (data_buf, tag_buf) = input.split_at(min(data_len, input.len()));
        self.cur += consumed;

        let mut out = Vec::new();

        // Read from the data buffer
        if !data_buf.is_empty() {
            // Create a decrypted buffer, with the proper size
            let block_size = self.cipher.block_size();
            let mut decrypted = vec![0u8; data_len + block_size];

            // Decrypt bytes
            // TODO: do not unwrap, but try error
            let len = self.crypter.update(data_buf, &mut decrypted)
                .expect("failed to update AES-GCM crypter with new data");

            // Add decrypted bytes to output
            out.extend_from_slice(&decrypted[..len]);
        }

        // Read from the tag part to fill the tag buffer
        if !tag_buf.is_empty() {
            self.tag.extend_from_slice(&tag_buf[..tag_len]);
        }

        // Verify the tag once available
        if self.has_tag() {
            // Set the tag
            // TODO: do not unwrap, but try error
            self.crypter.set_tag(&self.tag).expect("failed to set AES-GCM tag for validation");

            // Create a buffer for any remaining data
            let block_size = self.cipher.block_size();
            let mut extra = vec![0u8; block_size];

            // Finalize, write all remaining data
            // TODO: do not unwrap, but try error
            let len = self.crypter.finalize(&mut extra)
                .expect("failed to finalize AES-GCM crypter");
            out.extend_from_slice(&extra[..len]);

            // Set the verified flag
            // TODO: are we still using this?
            // self.verified = true;
        }

        let out = if !out.is_empty() {
            Some(out)
        } else {
            None
        };
        (consumed, out)
    }
}

impl Crypt for GcmCrypt {
    type Reader = GcmReader;
    type Writer = GcmWriter;

    fn crypt(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        match self.mode {
            CryptMode::Encrypt => self.enc(input),
            CryptMode::Decrypt => self.dec(input),
        }
    }
}

pub struct GcmReader {
    crypt: GcmCrypt,
    inner: Box<dyn Read>,
    buf_in: BytesMut,
    buf_out: BytesMut,
}

pub struct GcmWriter {
    crypt: GcmCrypt,
    inner: Box<dyn Write>,
    buf: BytesMut,
}

impl CryptRead<GcmCrypt> for GcmReader {
    fn new(crypt: GcmCrypt, inner: Box<dyn Read>) -> Self {
        Self {
            crypt,
            inner,
            // TODO: use proper buffer size
            buf_in: BytesMut::new(),
            buf_out: BytesMut::new(),
        }
    }
}

impl Read for GcmReader {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        // Number of bytes written to given buffer
        let mut total = 0;

        // TODO: do not attempt to completely fill the input buffer first for AES-GCM

        // Write any output buffer bytes first
        if !self.buf_out.is_empty() {
            // Copy as much as possible from inner to output buffer, increase total
            let write = cmp::min(self.buf_out.len(), buf.len());
            total += write;
            buf[..write].copy_from_slice(&self.buf_out.split_to(write));

            // Return if given buffer is full, or slice to unwritten buffer
            if total >= buf.len() {
                return Ok(total);
            }
            buf = &mut buf[write..];
        }

        // Attempt to fill input buffer if has capacity
        let capacity = self.buf_in.capacity() - self.buf_in.len();
        if capacity > 0 {
            // Read from inner to input buffer
            let mut inner_buf = vec![0u8; capacity];
            let read = self.inner.read(&mut inner_buf)?;
            self.buf_in.put(inner_buf);

            // If not enough input buffer data, we can't crypt, read nothing
            if read < capacity {
                return Ok(0);
            }
        }

        // Move input buffer into the crypter
        let (read, out) = self.crypt.crypt(&self.buf_in);
        self.buf_in.split_to(read);

        // Write any crypter output to given buffer and remaining to output buffer
        if let Some(out) = out {
            // Copy as much data as possible from crypter output to read buffer
            let write = cmp::min(out.len(), buf.len());
            total += write;
            buf[..write].copy_from_slice(&out[..write]);

            // Copy remaining bytes into output buffer
            if write < out.len() {
                self.buf_out.extend_from_slice(&out[write..]);
            }

            // Return if given buffer is full, or slice to unwritten buffer
            if write >= buf.len() {
                return Ok(total);
            }
            buf = &mut buf[write..];
        }

        // Try again with remaining given buffer
        self.read(buf).map(|n| n + total)
    }
}

impl CryptWrite<GcmCrypt> for GcmWriter {
    fn new(crypt: GcmCrypt, inner: Box<dyn Write>) -> Self {
        Self {
            crypt,
            inner,
            // TODO: use proper buffer size
            buf: BytesMut::new(),
        }
    }
}

impl Write for GcmWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // TODO: implement reader
        panic!("not yet implemented");
    }

    fn flush(&mut self) -> io::Result<()> {
        // TODO: implement this, flush as much as possible from buffer
        self.inner.flush()
    }
}

/// Something that can encrypt or decrypt given data using ECE.
pub struct EceCrypt {
    mode: CryptMode,
    seq: usize,

    // TODO: remove this buffer, obsolete?
    /// Input buffer.
    buf: BytesMut,
}

impl EceCrypt {
    pub fn new(mode: CryptMode, input_size: usize) -> Self {
        Self {
            mode,
            seq: 0,
            buf: BytesMut::with_capacity(input_size),
        }
    }
}

impl Crypt for EceCrypt {
    type Reader = EceReader;
    type Writer = EceWriter;

    fn crypt(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // How much to read, based on capacity that is left and given bytes
        let size = cmp::min(self.buf.capacity() - self.buf.len(), input.len());

        // Read bytes into the buffer
        self.buf.put(&input[0..size]);

        // TODO: encrypt/decrypt bytes, produce the result
        panic!("not yet implemented");
    }
}

pub struct EceReader {
    crypt: EceCrypt,
    inner: Box<dyn Read>,
    buf_in: BytesMut,
    buf_out: BytesMut,
}

pub struct EceWriter {
    crypt: EceCrypt,
    inner: Box<dyn Write>,
    buf: BytesMut,
}

impl CryptRead<EceCrypt> for EceReader {
    fn new(crypt: EceCrypt, inner: Box<dyn Read>) -> Self {
        Self {
            crypt,
            inner,
            // TODO: use proper buffer size
            buf_in: BytesMut::new(),
            buf_out: BytesMut::new(),
        }
    }
}

impl Read for EceReader {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        // Number of bytes written to given buffer
        let mut total = 0;

        // Write any output buffer bytes first
        if !self.buf_out.is_empty() {
            // Copy as much as possible from inner to output buffer, increase total
            let write = cmp::min(self.buf_out.len(), buf.len());
            total += write;
            buf[..write].copy_from_slice(&self.buf_out.split_to(write));

            // Return if given buffer is full, or slice to unwritten buffer
            if total >= buf.len() {
                return Ok(total);
            }
            buf = &mut buf[write..];
        }

        // Attempt to fill input buffer if has capacity
        let capacity = self.buf_in.capacity() - self.buf_in.len();
        if capacity > 0 {
            // Read from inner to input buffer
            let mut inner_buf = vec![0u8; capacity];
            let read = self.inner.read(&mut inner_buf)?;
            self.buf_in.put(inner_buf);

            // If not enough input buffer data, we can't crypt, read nothing
            if read < capacity {
                return Ok(0);
            }
        }

        // Move input buffer into the crypter
        let (read, out) = self.crypt.crypt(&self.buf_in);
        self.buf_in.split_to(read);

        // Write any crypter output to given buffer and remaining to output buffer
        if let Some(out) = out {
            // Copy as much data as possible from crypter output to read buffer
            let write = cmp::min(out.len(), buf.len());
            total += write;
            buf[..write].copy_from_slice(&out[..write]);

            // Copy remaining bytes into output buffer
            if write < out.len() {
                self.buf_out.extend_from_slice(&out[write..]);
            }

            // Return if given buffer is full, or slice to unwritten buffer
            if write >= buf.len() {
                return Ok(total);
            }
            buf = &mut buf[write..];
        }

        // Try again with remaining given buffer
        self.read(buf).map(|n| n + total)
    }
}

impl CryptWrite<EceCrypt> for EceWriter {
    fn new(crypt: EceCrypt, inner: Box<dyn Write>) -> Self {
        Self {
            crypt,
            inner,
            // TODO: use proper buffer size
            buf: BytesMut::new(),
        }
    }
}

impl Write for EceWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // TODO: implement reader
        panic!("not yet implemented");
    }

    fn flush(&mut self) -> io::Result<()> {
        // TODO: implement this, flush as much as possible from buffer
        self.inner.flush()
    }
}

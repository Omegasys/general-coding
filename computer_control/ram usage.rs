use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::Rng;
use x25519_dalek::{PublicKey, StaticSecret};
use sha2::{Sha256, Digest};

const RAM_BUFFER_LIMIT: usize = 1024 * 16; // Keep within CPU cache size

struct SecureRam {
    buffer: [u8; RAM_BUFFER_LIMIT],
    key: [u8; 32],
    next_key: Option<[u8; 32]>,
    used_size: usize,
}

impl SecureRam {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            buffer: [0u8; RAM_BUFFER_LIMIT],
            key,
            next_key: None,
            used_size: 0,
        }
    }

    /// Encrypt and write to RAM, ensuring buffer limit is not exceeded
    pub fn write_to_ram(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if self.used_size + data.len() + 12 > RAM_BUFFER_LIMIT {
            return Err("RAM buffer limit exceeded");
        }

        // Generate a random nonce (12 bytes for AES-GCM)
        let nonce = rand::thread_rng().gen::<[u8; 12]>();
        let cipher = Aes256Gcm::new(&Key::from_slice(&self.key));

        let encrypted_data = cipher.encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|_| "Encryption failed")?;

        // Store nonce + encrypted data into buffer
        let start = self.used_size;
        self.buffer[start..start + 12].copy_from_slice(&nonce);
        self.buffer[start + 12..start + 12 + encrypted_data.len()].copy_from_slice(&encrypted_data);

        self.used_size += 12 + encrypted_data.len();

        Ok(())
    }

    /// Read and decrypt data from RAM using double ratchet
    pub fn read_from_ram(&mut self) -> Result<Vec<u8>, &'static str> {
        if self.used_size < 12 {
            return Err("Insufficient data in buffer");
        }

        let nonce = &self.buffer[..12];
        let encrypted_data = &self.buffer[12..self.used_size];

        // Apply double ratchet key update before decryption
        if let Some(next_key) = self.next_key {
            self.key = next_key;
            self.next_key = None;
        }

        let cipher = Aes256Gcm::new(&Key::from_slice(&self.key));
        let decrypted_data = cipher.decrypt(Nonce::from_slice(nonce), encrypted_data)
            .map_err(|_| "Decryption failed")?;

        // Apply ratchet update after successful decryption
        self.update_ratchet_key();

        // Clear buffer after reading
        self.used_size = 0;

        Ok(decrypted_data)
    }

    /// Perform double ratchet key update
    fn update_ratchet_key(&mut self) {
        let ratchet_key = StaticSecret::new(rand::thread_rng());
        let public_key = PublicKey::from(&ratchet_key);

        // Derive a new key using SHA-256 from the ratchet key and public key
        let mut hasher = Sha256::new();
        hasher.update(ratchet_key.to_bytes());
        hasher.update(public_key.as_bytes());
        let next_key = hasher.finalize();

        self.next_key = Some(next_key.into());
    }
}

fn main() {
    let key = [0u8; 32];
    let mut secure_ram = SecureRam::new(key);

    let data = b"Secret data stored in cache";

    // Write to RAM
    match secure_ram.write_to_ram(data) {
        Ok(_) => println!("Data written to RAM."),
        Err(e) => println!("Error writing to RAM: {}", e),
    }

    // Read from RAM
    match secure_ram.read_from_ram() {
        Ok(decrypted_data) => println!("Decrypted data: {:?}", String::from_utf8(decrypted_data)),
        Err(e) => println!("Error reading from RAM: {}", e),
    }
}

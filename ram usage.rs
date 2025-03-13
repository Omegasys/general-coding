use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, KeyInit};
use rand::Rng;
use std::sync::{Arc, Mutex};

const RAM_BUFFER_LIMIT: usize = 1024 * 1024; // 1 MB limit

struct SecureRam {
    buffer: Arc<Mutex<Vec<u8>>>,
    key: Key<Aes256Gcm>,
}

impl SecureRam {
    pub fn new(key: &[u8]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        Self {
            buffer: Arc::new(Mutex::new(Vec::new())),
            key: key.clone(),
        }
    }

    /// Encrypt and write to RAM, ensuring buffer limit is not exceeded
    pub fn write_to_ram(&self, data: &[u8]) -> Result<(), &'static str> {
        let mut buffer = self.buffer.lock().unwrap();

        // Ensure buffer size doesn't exceed the limit
        if buffer.len() + data.len() > RAM_BUFFER_LIMIT {
            return Err("RAM buffer limit exceeded");
        }

        // Generate a random nonce (12 bytes for AES-GCM)
        let nonce = rand::thread_rng().gen::<[u8; 12]>();
        let cipher = Aes256Gcm::new(&self.key);

        // Encrypt the data
        let encrypted_data = cipher.encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|_| "Encryption failed")?;

        // Store nonce + encrypted data
        buffer.extend_from_slice(&nonce);
        buffer.extend_from_slice(&encrypted_data);

        Ok(())
    }

    /// Read and decrypt data from RAM
    pub fn read_from_ram(&self) -> Result<Vec<u8>, &'static str> {
        let mut buffer = self.buffer.lock().unwrap();

        if buffer.len() < 12 {
            return Err("Insufficient data in buffer");
        }

        let nonce = &buffer[..12];
        let encrypted_data = &buffer[12..];

        let cipher = Aes256Gcm::new(&self.key);

        // Decrypt the data
        let decrypted_data = cipher.decrypt(Nonce::from_slice(nonce), encrypted_data)
            .map_err(|_| "Decryption failed")?;

        // Clear buffer after reading
        buffer.clear();

        Ok(decrypted_data)
    }
}

fn main() {
    let key = [0u8; 32]; // 256-bit key for AES-256-GCM
    let secure_ram = SecureRam::new(&key);

    let data = b"Secret data that needs to be stored securely";

    // Write to RAM
    match secure_ram.write_to_ram(data) {
        Ok(_) => println!("Data written to RAM successfully."),
        Err(e) => println!("Error writing to RAM: {}", e),
    }

    // Read from RAM
    match secure_ram.read_from_ram() {
        Ok(decrypted_data) => println!("Decrypted data: {:?}", String::from_utf8(decrypted_data)),
        Err(e) => println!("Error reading from RAM: {}", e),
    }
}
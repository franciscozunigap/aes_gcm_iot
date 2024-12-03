use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use aes_gcm::aead::{Aead, Payload};    // Trait para cifrado autenticado y Payload
use aes_gcm::KeyInit;                  // Trait para inicializar el cifrado
use hkdf::Hkdf;
use sha2::Sha256;                      // Para HKDF
use rand::RngCore;                     // Para generar números aleatorios
use rand::rngs::OsRng;                 // Generador de números aleatorios seguro
use std::time::Instant;                // Para medir tiempos de ejecución
use std::fs::File;                     // Para guardar resultados
use std::io::Write;                    // Para escribir en archivos
use log::{info, error};                // Logs para auditoría y monitoreo

fn main() {
    // Inicializar logs con nivel de información
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    println!("Iniciando programa de cifrado AES-GCM");

    // Generar salt
    let mut salt = [0u8; 16]; // Salt de 128 bits
    OsRng.fill_bytes(&mut salt);
    info!("Salt generado correctamente.");

    // Configuración de tamaños de clave y datos
    let key_sizes = [16, 24, 32]; // Claves de 128, 192 y 256 bits
    let sizes = [1024, 102_400, 1_048_576, 5_242_880, 10_485_760, 52_428_800]; // 1 KB, 100 KB, 1 MB, 5 MB, 10 MB, 50 MB
    let iterations = 5;

    // Crear archivo para guardar resultados
    let mut file = File::create("resultados.csv").unwrap();
    writeln!(file, "Clave (bits),Tamaño de Datos (bytes),Promedio Cifrado (µs),Promedio Descifrado (µs)").unwrap();

    for &key_size in &key_sizes {
        println!("\nPruebas con clave de {} bits", key_size * 8);

        let mut master_key = vec![0u8; key_size];
        OsRng.fill_bytes(&mut master_key);

        let key = derive_key(&master_key, &salt);

        for &size in &sizes {
            println!("\nPrueba con tamaño de texto plano: {} bytes", size);

            let plaintext = vec![0u8; size];
            let associated_data = b"datos asociados";

            let mut total_encrypt_time = 0;
            let mut total_decrypt_time = 0;

            for _ in 0..iterations {
                // Medir tiempo de cifrado
                let start_encrypt = Instant::now();
                let (nonce, ciphertext) = encrypt(&key, &plaintext, associated_data).unwrap();
                total_encrypt_time += start_encrypt.elapsed().as_micros();

                // Medir tiempo de descifrado
                let start_decrypt = Instant::now();
                let decrypted_text = decrypt(&key, &nonce, &ciphertext, associated_data).unwrap();
                total_decrypt_time += start_decrypt.elapsed().as_micros();

                // Validar que el descifrado sea correcto
                if plaintext != decrypted_text {
                    error!("Validación fallida: El texto descifrado no coincide con el original.");
                    break;
                }
            }

            // Calcular promedios
            let avg_encrypt_time = total_encrypt_time / iterations;
            let avg_decrypt_time = total_decrypt_time / iterations;

            println!("Promedio de tiempo de cifrado: {} µs", avg_encrypt_time);
            println!("Promedio de tiempo de descifrado: {} µs", avg_decrypt_time);

            // Guardar resultados en el archivo
            writeln!(
                file,
                "{},{},{},{}",
                key_size * 8,
                size,
                avg_encrypt_time,
                avg_decrypt_time
            ).unwrap();
        }
    }

    println!("Resultados guardados en resultados.csv");
}

/// Función para derivar una clave usando HKDF
fn derive_key(master_key: &[u8], salt: &[u8]) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = [0u8; 32]; // Output Key Material de 256 bits
    hkdf.expand(b"iot-optimization", &mut okm).expect("HKDF expand failed");
    okm.to_vec()
}

/// Función para cifrar usando AES-GCM
fn encrypt(
    key: &[u8],
    plaintext: &[u8],
    associated_data: &[u8], // Se usa en autenticación
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_copy = nonce.clone();

    let nonce = Nonce::from_slice(&nonce);

    // Cifrar con datos asociados
    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    match cipher.encrypt(nonce, payload) {
        Ok(ciphertext) => Ok((nonce_copy.to_vec(), ciphertext)),
        Err(e) => Err(format!("Fallo en el cifrado: {:?}", e)),
    }
}

/// Función para descifrar usando AES-GCM
fn decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8], // Se usa en autenticación
) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    // Descifrar con datos asociados
    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    match cipher.decrypt(nonce, payload) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => Err(format!("Fallo en el descifrado: {:?}", e)),
    }
}

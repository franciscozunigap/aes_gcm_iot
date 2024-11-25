use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use aes_gcm::aead::{Aead, Payload};    // Trait para cifrado autenticado y Payload
use aes_gcm::KeyInit;                  // Trait para inicializar el cifrado
use hkdf::Hkdf;
use sha2::Sha256;                      // Para HKDF
use rand::RngCore;                     // Para generar números aleatorios
use rand::rngs::OsRng;                 // Generador de números aleatorios seguro
use std::time::Instant;                // Para medir tiempos de ejecución
use log::{info, error};                // Logs para auditoría y monitoreo

fn main() {
    // Inicializar logs con nivel de información
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    
    // También podemos agregar algunos println! para ver la información directamente
    println!("Iniciando programa de cifrado AES-GCM");

    // Generar clave maestra y salt
    let mut master_key = [0u8; 32]; // Clave maestra de 256 bits
    let mut salt = [0u8; 16];       // Salt de 128 bits
    OsRng.fill_bytes(&mut master_key);
    OsRng.fill_bytes(&mut salt);
    info!("Clave maestra y salt generados correctamente.");

    // Derivar la clave
    let key = derive_key(&master_key, &salt);
    info!("Clave derivada correctamente: {:?}.", key);

    // Datos asociados (constantes para las pruebas)
    let associated_data = b"datos asociados";

    // Tamaños de datos para las pruebas
    let sizes = [1024, 10_240, 102_400]; // 1 KB, 10 KB, 100 KB

    for size in &sizes {
        println!("\nPrueba con tamaño de texto plano: {} bytes", size);
        info!("Iniciando pruebas con tamaño de texto plano: {} bytes.", size);

        // Generar texto plano de tamaño `size`
        let plaintext = vec![0u8; *size];

        // Medir tiempo de cifrado
        let start_encrypt = Instant::now();
        let (nonce, ciphertext) = match encrypt(&key, &plaintext, associated_data) {
            Ok(result) => result,
            Err(e) => {
                error!("Error durante el cifrado: {}", e);
                continue;
            }
        };
        let duration_encrypt = start_encrypt.elapsed();
        info!(
            "Cifrado completado en {:?}. Nonce utilizado: {:?}",
            duration_encrypt, nonce
        );

        println!("Tiempo de cifrado: {:?}", duration_encrypt);

        // Medir tiempo de descifrado
        let start_decrypt = Instant::now();
        let decrypted_text = match decrypt(&key, &nonce, &ciphertext, associated_data) {
            Ok(result) => result,
            Err(e) => {
                error!("Error durante el descifrado: {}", e);
                continue;
            }
        };
        let duration_decrypt = start_decrypt.elapsed();
        info!(
            "Descifrado completado en {:?}. Primeros 32 bytes del descifrado: {:?}",
            duration_decrypt,
            &decrypted_text[..32]
        );

        println!("Tiempo de descifrado: {:?}", duration_decrypt);

        // Verificar que el descifrado sea correcto
        if plaintext == decrypted_text {
            info!("Validación exitosa: El texto descifrado coincide con el original.");
        } else {
            error!("Validación fallida: El texto descifrado no coincide con el original.");
        }

        // Línea en blanco para separar casos
        println!("--------------------------------------------");
    }
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

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello, world!");
    let dir_path = "random";

    let _ = encrypt_dir(dir_path);
    Ok(())
}

fn encrypt_dir(dir_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dir = fs::read_dir(dir_path).unwrap();
    let mut rng = rand::thread_rng();

    let bits = 2048;

    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate private key");
    let pub_key = RsaPublicKey::from(&priv_key);
    for file in dir {
        println!("{file:?}");
        let path = file?;

        let ind_file = fs::read_to_string(path.path())?;
        println!("{ind_file:?}");
        let enc_data = encrypt_files(&ind_file, pub_key.clone())?;
        let _ = decrypt_files(enc_data, priv_key.clone());
    }
    Ok(())
}

fn encrypt_files(
    ind_file: &str,
    pub_key: RsaPublicKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    let data = ind_file.as_bytes();
    let enc_data = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &data[..])
        .expect("failed to encrypt");

    println!("{enc_data:?}");
    Ok(enc_data)
}

fn decrypt_files(
    enc_data: Vec<u8>,
    priv_key: RsaPrivateKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let dec_data = priv_key.decrypt(Pkcs1v15Encrypt, &enc_data);
    println!("\n decrypted data");
    println!(" {dec_data:?}");
    Ok(())
}

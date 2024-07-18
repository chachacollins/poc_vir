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
    for file in dir {
        println!("{file:?}");
        let path = file?;

        let ind_file = fs::read_to_string(path.path())?;
        println!("{ind_file:?}")
    }
    Ok(())
}

fn encrypt_files(ind_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    let bits = 2048;

    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate private key");
    let pub_key = RsaPublicKey::from(priv_key);
    Ok(())
}

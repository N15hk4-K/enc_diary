use std::fs; //to read files
use std::io::ErrorKind; 
use argon2::Argon2; //for password hashing
use chacha20poly1305::{aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce
}; //for encryption
//use std::error::Error;  was needed for Box<dyn Error>
use std::path::Path; //handles filesystem paths
use std::process::Command; // configures and runs system commands
use rpassword::prompt_password; //to take password as input

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

pub fn call_editor(path: &String) -> Result<(), String>{
    let password = rpassword::prompt_password("Password: ")
        .map_err(|_| "Unexpected Error while reading password".to_string())?;

    // existing diary -> decrypt it; new diary -> start empty
    let original = if Path::new(path).exists() {
        let contents = get_contents(path)?;
        decrypt(&password, &contents)?
    } else {
        Vec::new()
    };

    let tmp = format!("/tmp/diary-{}.txt", std::process::id());
    write_file(&tmp, &original)?;
    let result = run_editor(&tmp, &password, path);
    let _ = fs::remove_file(&tmp); // runs whether run_editor succeeded or failed
    result
}

pub fn run_editor(tmp: &String, password: &str, path: &str) -> Result<(), String> {
    let status = Command::new("vim").args(["-n", "-i", "NONE", tmp]).status()
        .map_err(|_| format!("Could not open vim"))?;
    if !status.success() {
        return Err("editor exited with an error".to_string());
    }
    let edited = get_contents(tmp)?;
    let encrypted = encrypt(&password, &edited)?;
    write_file(path, &encrypted)
}

pub fn call_viewer(path: &String) -> Result<(), String> {
    let password = prompt_password("Password: ")
        .map_err(|_| "Unexpected error while reading password".to_string())?;
    let plain = decrypt(&password, &get_contents(path)?)?;

    let tmp = format!("/tmp/diary-view-{}.txt", std::process::id());
    write_file(&tmp, &plain)?;

    let status = Command::new("vim").args(["-R", "-n", "-i", "NONE", &tmp]).status();
    let _ = fs::remove_file(&tmp);                 // always clean up

    let status = status.map_err(|_| format!("Could not open vim"))?;
    if !status.success() {
        return Err("Viewer exited with an error".to_string());
    }
    Ok(())
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32],String> {
    // Box<dyn Error> is for any kind of error i had initially used it, but then i changed to
    // string to get cleaner error handling
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| "Key generation failed".to_string())?;
    // the ? returns if there is an error, or else it continues
    Ok(key)
}

pub fn encrypt(password: &str, plaintext: &[u8]) -> Result<Vec<u8>,String> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt); //this should not fail, even if it did, program will panic

    let key = derive_key(&password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); //same as fill_bytes for this
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| "encryption failed".to_string())?;

    let mut out = Vec::new();
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt(password: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err("file too short to be valid".to_string());
    }

    let salt = &data[..SALT_LEN];
    let nonce = Nonce::from_slice(&data[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let key = derive_key(&password, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "wrong password or corrupted file".to_string())
}

pub fn get_contents(file_path: &String) -> Result<Vec<u8>, String> {
    match fs::read(file_path) {
        Ok(data) => Ok(data),
        Err(error) => {
            match error.kind() {
                ErrorKind::NotFound => Err("File Not Found".to_string()),
                ErrorKind::PermissionDenied => Err("Permission denied".to_string()),
                _ => Err("Unexpected Error while reading file".to_string())
            }
        }
    }
}

fn write_file(path: &str, data: &[u8]) -> Result<(), String> {
    fs::write(path, data).map_err(|e| format!("Failed to write {path}: {e}"))
}

pub fn encrypt_this(file_path: &String) -> Result<(), String> {
    let contents = get_contents(file_path)?; // this returns from the current function if the value
                                             // is Err, otherwise it gives the Ok value
    //let password = match rpassword::prompt_password("Password? : ") {
    //    Ok(password) => password,
    //    Err(_) => {
    //        return Err("Unexpected Error while reading password".to_string());
    //    }
    //};   --> this was my initial attempt, but the below code is more compact
    
    let password = rpassword::prompt_password("Password? : ")
        .map_err(|_| "Unexpected error while reading passsword".to_string())?;

    let cipher_text = encrypt(&password, &contents)?;
    let out_path = encrypted_name(file_path, 1);
    write_file(&out_path, &cipher_text)?;
    println!("Encrypted file written to {out_path}");
    Ok(())
}

pub fn decrypt_this(file_path: &String) -> Result<(), String> {
    let contents = get_contents(file_path)?;
    let password = rpassword::prompt_password("Password? : ")
        .map_err(|_| "Unexpected error while reading password".to_string())?;
    let plain_text = decrypt(&password, &contents)?;
    let out_path = encrypted_name(file_path, 2);
    write_file(&out_path, &plain_text)?;
    println!("Decrypted file written to {out_path}");
    Ok(())
}

fn encrypted_name(file_path: &str, option: u8) -> String {
    let path = Path::new(file_path);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");

    let suff = if option==1 {"enc"} else {"denc"};

    let new_name = match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{stem}_{suff}.{ext}"),
        None => format!("{stem}_{suff}"),
    };

    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => {
            dir.join(new_name).to_string_lossy().into_owned()
        }
        _ => new_name,
    }
}

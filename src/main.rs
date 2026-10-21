use std::env; //to read the command line arguments passed to the program
use std::fs; //to read files
use std::io::ErrorKind; 
use argon2::Argon2; //for password hashing
use chacha20poly1305::{aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce
}; //for encryption
use std::error::Error;
use std::path::Path; //handles filesystem paths
use std::process::Command; // configures and runs system commands
use rpassword::prompt_password; //to take password as input

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

fn call_editor(path: &str) {
    let password = match rpassword::prompt_password("Password: "){
        Ok(password) => password,
        Err(_) => {
            println!("Unexpected Error while reading password");
            return;
        }
    };
    // existing diary -> decrypt it; new diary -> start empty
    let original = if Path::new(path).exists() {
        decrypt(&password, &fs::read(path)?)?
    } else {
        Vec::new()
    };

    let tmp = format!("/tmp/{}.txt", Path::new(path).file_stem().unwrap().to_str().unwrap());
    fs::write(&tmp, &original)?;
    let result = run_editor(&tmp, &password, path);
    let _ = fs::remove_file(&tmp); // runs whether run_editor succeeded or failed
    match result {
        Ok(_) => {}
        Err(_) => {
            println!("Editor exited with an error");
        }
    };
}

fn run_editor(tmp: &str, password: &str, path: &str) -> Result<(), Box<dyn Error>> {
    let status = Command::new("vim").args(["-n", "-i", "NONE", tmp]).status()?;
    if !status.success() {
        return Err("editor exited with an error".into());
    }
    let edited = fs::read(tmp)?;
    let encrypted = encrypt(&password, &edited)?;
    fs::write(path, &encrypted)?;
    Ok(())
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    // Box<dyn Error> is for any kind of error
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)?;
    // the ? returns if there is an error, or else it continues
    Ok(key)
}

fn encrypt(password: &str, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(&password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| "encryption failed")?;

    let mut out = Vec::new();
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(password: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err("file too short to be valid".into());
    }

    let salt = &data[..SALT_LEN];
    let nonce = Nonce::from_slice(&data[SALT_LEN..SALT_LEN + NONCE_LEN]);
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let key = derive_key(&password, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "wrong password or corrupted file")?;
    Ok(plaintext)
}

fn encrypt_this(file_path: &String) {
    let contents = match fs::read(file_path) {
        Ok(data) => data,
        Err(error) => {
            match error.kind() {
                ErrorKind::NotFound => println!("File Not Found"),
                ErrorKind::PermissionDenied => println!("Permission denied"),
                _ => println!("Unexpected Error while reading file")
            };
            return;
        }
    };

    let password = match rpassword::prompt_password("Password? : ") {
        Ok(password) => password,
        Err(_) => {
            println!("Unexpected Error while reading password");
            return;
        }
    };

    let cipher_text = encrypt(&password, contents);
    let _ = fs::write("poem_enc.txt", cipher_text);
}

fn decrypt_this(file_path: &String) {
    let contents = match fs::read(file_path) {
        Ok(data) => data,
        Err(error) => {
            match error.kind() {
                ErrorKind::NotFound => println!("File Not Found"),
                ErrorKind::PermissionDenied => println!("Permission denied"),
                _ => println!("Unexpected Error while reading file")
            };
            return;
        }
    };
    let password = match rpassword::prompt_password("Password? : ") {
        Ok(password) => password,
        Err(_) => {
            println!("Unexpected Error while reading password");
            return;
        }
    };
    let plain_text = decrypt(&password, contents).unwrap();
    let _ = fs::write("poem_enc_denc.txt", &plain_text);
}

fn main() {
    let args: Vec<String> = env::args().collect(); //args() returns an iterator of the command line
                                                   //arguments passed to it; collect method turns
                                                   //an iterator into a collection
    dbg!(&args); //to print the args
    println!("{:?}",args); //have to do it like this cuz vector doesn't implement the Display trait
    if args.len()!=3 {
        println!("Usage: enc-diary <decrypt/encrypt/edit> <file_path>");
        return;
    }
    match args[1].as_str() { // args[1] is a String, we are comparing it with str values
        "decrypt" => {
            println!("You typed decrypt!");
            decrypt_this(&args[2]);
        }
        "encrypt" => {
            println!("You typed encrypt!");
            encrypt_this(&args[2]);
        }
        "edit" => {
            println!("You typed edit!");
            call_editor(&args[2]);
        }
        _ => {
            println!("Usage: enc-diary <decrypt/encrypt/edit> <file_path>");
            return;
        }
    };
    return;
}


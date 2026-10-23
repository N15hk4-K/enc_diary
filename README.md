# enc_diary: Encrypted Diary
A command-line tool written in Rust that stores files in a password-encrypted format, and lets you view and edit them using vim, with plaintext lives briefly in `/tmp`.

## Build
Requires Rust and vim. Linux, macOS, or WSL (it uses `/tmp` and vim).
```
cargo build --release
```

## Usage
```
cargo run -- <command> <file>
enc_diary <command> <file>  #if the build is done
```

## Command | What it does

1) `edit <file>` | Decrypt to `/tmp`, open in vim, re-encrypt on exit. Creates a new diary if the file doesn't exist.
2) `view <file>` | Decrypt to `/tmp`, open in vim read-only, delete on exit.
3) `encrypt <file>` | Encrypt a plaintext file into `<name>_enc.<ext>`.
4) `decrypt <file>` | Decrypt a file into `<name>_denc.<ext>`.

Example:
```
cargo run -- edit my_diary.enc     # write an entry (prompts for password)
cargo run -- view my_diary.enc     # read it 
```

The password is typed without being shown on screen.

## encrypted file format
```
| salt (16 bytes) | nonce (12 bytes) | ciphertext + authentication tag |
```

A wrong password or a modified file is detected and reported as `wrong password or corrupted file`.
Random values come from the operating system's random source (`OsRng`).

## Temporary file handling
- Temp files are created in `/tmp` with a name including the process id, so separate runs don't collide.
- vim is launched with `-n -i NONE` so it doesn't write swap or viminfo files that could leak plaintext. The viewer also uses `-R` (read-only).
- The temp file is deleted after the editor exits, whether it succeeded or failed.

## Error handling
Functions return `Result<_, String>` and use `?` to pass errors upward. Only `main` prints the error and exits with a non-zero status, so messages such as `File not found` or `wrong password or corrupted file` are written in one place.

## Dependencies
- `argon2`: password-based key derivation
- `chacha20poly1305`: authenticated encryption
- `rpassword`: reading the password without echo

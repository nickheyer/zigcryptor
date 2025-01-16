# zigcryptor

<div align="center">
    <p>File encryption/decryption utility written in Zig. </p>
    <img src="logo.jpg" alt="zigcryptor logo" width="50%">
</div>


## Build

```
zig build
```

## Usage

```
zigcryptor <encrypt|decrypt> <input_file> <password>
```

## Example

```bash
# Encrypt - Returns <input-file>.enc
zigcryptor encrypt secret.txt mypassword

# Decrypt - Returns <input-file>.dec
zigcryptor decrypt secret.txt.enc mypassword
```

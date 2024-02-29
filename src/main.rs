use pqc_kyber::*;
use sharks::{ Sharks, Share };
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305,
    Key,
};
use std::str;
use rand::{rngs::StdRng, SeedableRng};
use argon2::Argon2;
use std::{sync::{Arc, Mutex}};
use sled::{Db};
use serde::{Serialize, Deserialize};
use crystals_dilithium::dilithium5::{Keypair, PublicKey, SecretKey};

#[derive(Serialize, Deserialize)]
struct User {
    id: u64,
    salt: Option<Vec<u8>>,
    public_key_kyber: Vec<u8>,
    public_key_dilithium: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Passkey {
    id: u64,
    user_id: u64,
    nonce1: Vec<u8>,
    nonce2: Vec<u8>,
    password_cipher: Vec<u8>,
    metadata: Metadata,
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    site : Option<String>,
    service_name: Option<String>,
    username: Option<String>,
    otp_string: Option<Vec<u8>>,
}

struct PasswordManager {
    db: Arc<Mutex<Db>>,
}

impl PasswordManager {
    fn new() -> Self {
        let db = Arc::new(Mutex::new(sled::open("password_manager.db").unwrap()));
        Self { db }
    }

    fn get_user(&self, id: u64) -> Option<User> {
        let db = self.db.lock().unwrap();
        let tree = db.open_tree("users").unwrap();
        let serialized_user = tree.get(serde_json::to_vec(&id.to_be_bytes()).unwrap()).unwrap()?;
        serde_json::from_slice(&serialized_user).unwrap()
    }

    fn get_passkey(&self, id: u64) -> Option<Passkey> {
        let db = self.db.lock().unwrap();
        let tree = db.open_tree("passkeys").unwrap();
        let serialized_passkey = tree.get(serde_json::to_vec(&id.to_be_bytes()).unwrap()).unwrap()?;
        serde_json::from_slice(&serialized_passkey).unwrap()
    }

    fn create_user(&mut self, user: User) -> u64 {
        let db = self.db.lock().unwrap();
        let tree = db.open_tree("users").unwrap();
        let id: u64;
        if !tree.last().unwrap().is_some() {
            id = 0;
        } else {
            let (lastid, _) = tree.last().unwrap().unwrap();
            id = u64::from_be_bytes(serde_json::from_slice::<[u8;8]>(&lastid).unwrap()) + 1;
        }
        tree.insert(serde_json::to_vec(&id.to_be_bytes()).unwrap(), serde_json::to_vec(&user).unwrap()).unwrap();
        id
    }

    fn create_passkey(&mut self, passkey: Passkey) -> u64 {
        let db = self.db.lock().unwrap();
        let tree = db.open_tree("passkeys").unwrap();
        let id: u64;
        if !tree.last().unwrap().is_some() {
            id = 0;
        } else {
            let (lastid, _) = tree.last().unwrap().unwrap();
            id = u64::from_be_bytes(serde_json::from_slice::<[u8;8]>(&lastid).unwrap()) + 1;
        }
        tree.insert(serde_json::to_vec(&id.to_be_bytes()).unwrap(), serde_json::to_vec(&passkey).unwrap()).unwrap();
        id
    }

    fn update_user(&mut self, user: User) {
        let db = self.db.lock().unwrap();
        let tree = db.open_tree("users").unwrap();
        tree.insert(serde_json::to_vec(&user.id.to_be_bytes()).unwrap(), serde_json::to_vec(&user).unwrap()).unwrap();
    }

    fn update_passkey(&mut self, passkey: Passkey) {
        let db = self.db.lock().unwrap();
        let tree = db.open_tree("passkeys").unwrap();
        tree.insert(serde_json::to_vec(&passkey.id.to_be_bytes()).unwrap(), serde_json::to_vec(&passkey).unwrap()).unwrap();
    }

    fn delete_user(&mut self, id: u64) {
        let db = self.db.lock().unwrap();
        let tree = db.open_tree("users").unwrap();
        tree.remove(serde_json::to_vec(&id.to_be_bytes()).unwrap()).unwrap();
    }

    fn delete_passkey(&mut self, id: u64) {
        let db = self.db.lock().unwrap();
        let tree = db.open_tree("passkeys").unwrap();
        tree.remove(serde_json::to_vec(&id.to_be_bytes()).unwrap()).unwrap();
    }
}
fn main() {
    use std::io::{stdin};
    println!("Please choose an option: ");
    let mut s=String::new();
    stdin().read_line(&mut s).expect("Did not enter a correct string");
    s = s.trim().to_string();
    if &s == "shards" {
        let mut rng = OsRng;
        let keys_bob = keypair(&mut rng).unwrap();
        let messagehash = blake3::hash(&keys_bob.secret);
        let messagekey: &Key = Key::from_slice(messagehash.as_bytes());
        let messagecipher =XChaCha20Poly1305::new(messagekey);
        let messagenonce = XChaCha20Poly1305::generate_nonce(&mut rng);
        let messageciphertext = messagecipher.encrypt(&messagenonce, b"SUU".as_ref()).unwrap();
        let (ciphertext, shared_secret_alice) = encapsulate(&keys_bob.public, &mut rng).unwrap();
        let sharks = Sharks(3);
        let dealer = sharks.dealer(&keys_bob.secret.clone());
        let shares: Vec<Share> = dealer.take(9).collect();
        let hash = blake3::hash(&shared_secret_alice);
        let key: &Key = Key::from_slice(hash.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rng); // 192-bits; unique per message
        let ciphertex = cipher.encrypt(&nonce, messageciphertext.as_slice()).unwrap();
        let y = [shares[1].clone(), shares[4].clone(), shares[6].clone()];
        let secret = sharks.recover(y.as_slice()).unwrap();
        let shared_secret_bob = decapsulate(&ciphertext, &secret).unwrap();
        assert_eq!(shared_secret_bob, shared_secret_alice);
        let hash = blake3::hash(&shared_secret_bob);
        let key: &Key = Key::from_slice(hash.as_bytes()).into();
        let cipher = XChaCha20Poly1305::new(key);
        let plaintext = cipher.decrypt(&nonce, ciphertex.as_ref()).unwrap();
        let message = messagecipher.decrypt(&messagenonce, plaintext.as_slice()).unwrap();
        println!("Plaintext {}", str::from_utf8(message.as_slice()).unwrap());
        println!("Communicated ciphertext ciphertex nonce messagenonce");
        println!("You need to store shards in different location to stay secure like 2 on your phone in different folders one in cloud one on a usb and 2 on your computer you need at least 3 shards to unlock the account");
    } else if &s == "password" {
        let mut rng = OsRng;
        let password = b"UndressRubbleStubbornHullPremisesAppetizerCompoundCache";
        let mut salt = [0u8; 32]; 
        let mut output = [0u8; 32];
        rng.fill_bytes(&mut salt);
        Argon2::default().hash_password_into(password, &salt, &mut output).unwrap();
        let mut seeded_rng = StdRng::from_seed(output);
        let keys_bob = keypair(&mut seeded_rng).unwrap();
        let messagehash = blake3::hash(&keys_bob.secret);
        let messagekey: &Key = Key::from_slice(messagehash.as_bytes());
        let messagecipher =XChaCha20Poly1305::new(messagekey);
        let messagenonce = XChaCha20Poly1305::generate_nonce(&mut rng);
        let messageciphertext = messagecipher.encrypt(&messagenonce, b"SUU".as_ref()).unwrap();
        let (ciphertext, shared_secret_alice) = encapsulate(&keys_bob.public, &mut rng).unwrap();
        let hash = blake3::hash(&shared_secret_alice);
        let key: &Key = Key::from_slice(hash.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rng); // 192-bits; unique per message
        let ciphertex = cipher.encrypt(&nonce, messageciphertext.as_slice()).unwrap();
        let password = b"UndressRubbleStubbornHullPremisesAppetizerCompoundCache";
        let mut output = [0u8; 32];
        Argon2::default().hash_password_into(password, &salt, &mut output).unwrap();
        let mut seeded_rng = StdRng::from_seed(output);
        let keys_bob = keypair(&mut seeded_rng).unwrap();
        let secret = keys_bob.secret;
        let shared_secret_bob = decapsulate(&ciphertext, &secret).unwrap();
        assert_eq!(shared_secret_bob, shared_secret_alice);
        let hash = blake3::hash(&shared_secret_bob);
        let key: &Key = Key::from_slice(hash.as_bytes()).into();
        let cipher = XChaCha20Poly1305::new(key);
        let plaintext = cipher.decrypt(&nonce, ciphertex.as_ref()).unwrap();
        let message = messagecipher.decrypt(&messagenonce, plaintext.as_slice()).unwrap(); 
        println!("Plaintext {}", str::from_utf8(message.as_slice()).unwrap());
        println!("Communicated ciphertext ciphertex nonce salt messagenonce");


    } else if  &s == "homoc" {
        use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint64};
        use tfhe::prelude::*;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        let name = "google.com";
        let mut hasher = DefaultHasher::new();
        hasher.write(&name.as_bytes());
        let num = hasher.finish();
        let mut hasher = DefaultHasher::new();
        hasher.write(b"google.com");
        let num2 = hasher.finish();
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        let a = FheUint64::encrypt(num, &client_key);
        set_server_key(server_key);
        let result = a.eq(num2);
        let decrypted_result: bool = result.decrypt(&client_key);
        println!("{}", decrypted_result);
    } else if &s == "db" { 
        let mut password_manager = PasswordManager::new();

        // Create a new user.
        let user_id = password_manager.create_user(User {
            id: 0,
            salt: None,
            public_key_kyber: vec![0; 1568],
            public_key_dilithium: vec![0; 2592],
        });

        // Create a new passkey for the user.
        let passkey_id = password_manager.create_passkey(Passkey {
            id: 0,
            user_id,
            nonce1: vec![0; 16],
            nonce2: vec![0; 16],
            password_cipher: vec![0; 32],
            metadata: Metadata {
                site: Some("example.com".to_string()),
                service_name: Some("Example Service".to_string()),
                username: Some("username".to_string()),
                otp_string: None,
            },
        });
        let user_id = password_manager.create_user(User {
            id: 1,
            salt: None,
            public_key_kyber: vec![0; 1568],
            public_key_dilithium: vec![0; 2592],
        });

        // Create a new passkey for the user.
        let passkey_id = password_manager.create_passkey(Passkey {
            id: 1,
            user_id,
            nonce1: vec![0; 16],
            nonce2: vec![0; 16],
            password_cipher: vec![0; 32],
            metadata: Metadata {
                site: Some("example.com".to_string()),
                service_name: Some("Example Service".to_string()),
                username: Some("username".to_string()),
                otp_string: None,
            },
        });
        // Get the user and passkey by their IDs.
        let user = password_manager.get_user(user_id).unwrap();
        let passkey = password_manager.get_passkey(passkey_id).unwrap();
        println!("{}", user.id);
        println!("{}", passkey.metadata.username.unwrap());

        // Update the user and passkey.
        password_manager.update_user(User {
            id: user.id,
            salt: Some(vec![1; 16]),
            public_key_kyber: vec![1; 1568],
            public_key_dilithium: vec![1; 2592],
        });
        password_manager.update_passkey(Passkey {
            id: passkey.id,
            user_id,
            nonce1: vec![1; 16],
            nonce2: vec![1; 16],
            password_cipher: vec![1; 32],
            metadata: Metadata {
                site: Some("example.com".to_string()),
                service_name: Some("Example Service".to_string()),
                username: Some("username".to_string()),
                otp_string: Some(vec![1; 16]),
            },
        });

        // Delete the user and passkey.
        password_manager.delete_user(user_id);
        password_manager.delete_passkey(passkey_id);
        password_manager.delete_user(0);
        password_manager.delete_passkey(0);

    } else if &s == "auth" {
        let mut rng = OsRng;
        let keypaira = Keypair::generate(None);
        let public_key = keypaira.public;
        let secret_key = keypaira.secret;
        let public_key_bytes = public_key.to_bytes();
        let server_public_key = PublicKey::from_bytes(&public_key_bytes); // public_key_bytes is send to the server
        let mut buf = [0u8; 256];
        rng.fill_bytes(&mut buf);
        let challenge_hash = blake3::hash(&buf);
        let challenge = challenge_hash.as_bytes(); // challenge is sent back to the client
        let sign = secret_key.sign(challenge); // sign is sent to the server
        let verify = server_public_key.verify(challenge, &sign); 
        if verify {
            println!("Authorized");
        } else {
            println!("Not Authorized");
        }
        println!("Communicated public_key_bytes challenge sign and the response");
    } else if &s == "rotation" {
        fn generate_server_secret() -> Vec<u8> {
            let mut rng = OsRng;
            let mut secret = vec![0; 32];
            rng.fill_bytes(&mut secret);
            secret
        }

        fn derive_user_key_salt(public_key: &[u8], server_secret: &[u8]) -> (Vec<u8>,Vec<u8>){
            let mut output = [0u8; 32];
            let mut rng = OsRng;
            let info = [b"user database key", public_key, server_secret].concat(); // additional context info for the derived key        
            let mut salt = vec![0;32];
            rng.fill_bytes(&mut salt);
            Argon2::default().hash_password_into(&info, salt.as_slice(), &mut output).unwrap();
            (output.to_vec(), salt)
        }
        
        fn derive_user_key(public_key: &[u8], server_secret: &[u8], salt: &[u8]) -> Vec<u8>{
            let mut output = [0u8; 32];
            let info = [b"user database key", public_key, server_secret].concat(); // additional context info for the derived key        
            Argon2::default().hash_password_into(&info, salt, &mut output).unwrap();
            output.to_vec()
        }


        fn encrypt_password(database_key: &[u8], password: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let mut rng = OsRng;
            let key = Key::from_slice(database_key);
            let messagecipher =XChaCha20Poly1305::new(key);
            let messagenonce = XChaCha20Poly1305::generate_nonce(&mut rng);
            let messageciphertext = messagecipher.encrypt(&messagenonce, password).unwrap();
            (messageciphertext, messagenonce.to_vec())
        }

        fn decrypt_password(database_key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Vec<u8> {
            let key = Key::from_slice(database_key);
            let messagecipher =XChaCha20Poly1305::new(key);
            let password = messagecipher.decrypt( chacha20poly1305::XNonce::from_slice(nonce), ciphertext).unwrap();
           
            password
        }
        let server_secret = generate_server_secret();
        let keypair = keypair(&mut OsRng).unwrap();
        let public_key = keypair.public.to_vec();
        use std::collections::HashMap;
        let mut user_data = Vec::new();
        let mut temp_mem_user = Vec::new();
        struct User {
            password: Vec<u8>,
            salt: Option<Vec<u8>>,
            public_key: Vec<u8>,
            nonce: Option<Vec<u8>>,
        }
        let user_1 = User {
            salt: None,
            public_key: public_key.clone(),
            password: b"SALUT".to_vec(),
            nonce: None,
        };
        temp_mem_user.push(user_1);
        for i in temp_mem_user.iter_mut() {
            let (database_key, salt) = derive_user_key_salt(&i.public_key, &server_secret);
            i.salt = Some(salt);
            let (password, nonce) = encrypt_password(&database_key, &i.password);
            i.password = password;
            i.nonce = Some(nonce);
        }
        user_data = temp_mem_user;
        let nonce = <std::option::Option<Vec<u8>> as Clone>::clone(&user_data[0].nonce).unwrap();
        let pp = decrypt_password(&derive_user_key(&public_key, &server_secret,&<std::option::Option<Vec<u8>> as Clone>::clone(&user_data[0].salt).unwrap()),&user_data[0].password,&nonce);
        println!("{}", str::from_utf8(pp.as_slice()).unwrap());
    } else {
        println!("\n Unknown option \nCurrent possible options : shards; password; homoc; db; auth; rotation");
    }
}

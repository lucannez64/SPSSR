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
use uuid::Uuid;
use std::collections::HashMap;

use tonic::{Request, Response, Status};

pub mod qusend {
    tonic::include_proto!("qusend");
}

use qusend::{
    password_manager_server::{PasswordManager, PasswordManagerServer},
    AddPasswordRequest, AddPasswordResponse, AuthenticateRequest, AuthenticateResponse,
    CreateUserRequest, CreateUserResponse, DeletePasswordRequest, DeletePasswordResponse,
    InitCommunicationRequest, InitCommunicationResponse, ListPasswordsRequest,
    ListPasswordsResponse, PasswordMetadata, RetrievePasswordRequest, RetrievePasswordResponse,
    UpdatePasswordRequest, UpdatePasswordResponse,
};

#[derive(Debug, Default)]
struct PasswordManagerService {
    users: Arc<Mutex<HashMap<i64, UserData>>>,
    challenges: Arc<Mutex<HashMap<i64,Vec<u8>>>>
}

#[derive(Debug, Default)]
struct UserData {
    public_dilithium_key: Vec<u8>,
    public_kyber_key: Vec<u8>,
    salt: Vec<u8>,
    passwords: HashMap<i64, PasswordEntry>,
    auth_token: i64,
}

#[derive(Debug, Default)]
struct PasswordEntry {
    ciphertext: Vec<u8>,
    metadata: PasswordMetadata,
}

#[tonic::async_trait]
impl PasswordManager for PasswordManagerService {
    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::new_v4();
        let user_id = id.as_64();
        let user_data = UserData {
            public_dilithium_key: req.public_dilithium_key,
            public_kyber_key: req.public_kyber_key,
            salt: req.salt,
            ..Default::default()
        };
        self.users.lock().unwrap().insert(user_id, user_data);

        let response = CreateUserResponse {
            id: user_id,
            code: 0,
        };
        Ok(Response::new(response))
    }

    async fn init_communication(
        &self,
        request: Request<InitCommunicationRequest>,
    ) -> Result<Response<InitCommunicationResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.user_id;
        let mut rng = OsRng;
        let user_data = self.users.lock().unwrap().get(&user_id).ok_or_else(|| {
            Status::not_found("User not found")
        })?; 
        let user_public_key = user_data.public_kyber_key;
        let (ciphertext, shared_secret) = encapsulate(&user_public_key, &mut rng).unwrap();

        let response = InitCommunicationResponse { ciphertext: ciphertext.to_vec() };
        Ok(Response::new(response))
    }

    async fn authenticate_start(
        &self,
        request: Request<AuthenticateStartRequest>,
    ) -> Result<Response<AuthenticateStartResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.user_id;
        let user_data = self.users.lock().unwrap().get(&user_id).ok_or_else(|| {
            Status::not_found("User not found")
        })?;
        let mut rng = OsRng; 
        let mut buf = [0u8; 256];
        rng.fill_bytes(&mut buf);
        let challenge_hash = blake3::hash(&buf);
        let challenge = challenge_hash.as_bytes();
        self.challenges.lock().unwrap().insert(user_id, challenge.to_vec() );
        let response = AuthenticateStartResponse { challenge };

        Ok(Response::new(response))
    }

    async fn authenticate(
        &self,
        request: Request<AuthenticateRequest>,
    ) -> Result<Response<AuthenticateResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.user_id;
        let signature = req.signature;
        let user_data = self.users.lock().unwrap().get(&user_id).ok_or_else(|| {
            Status::not_found("User not found")
        })?;
        let user_public_key = PublicKey::from_bytes(user_data.public_dilithium_key);
        let challenge = self.challenges.lock().unwrap().get(&user_id).ok_or_else(|| {
            Status::not_found("User not found")
        })?;

        let signature_valid = user_public_key.verify(challenge.as_slice(), &signature);
        if !signature_valid {
            return Err(Status::unauthenticated("Invalid signature"));
        }

        let auth_token = todo!()/* generate auth token */;
        user_data.auth_token = auth_token;

        let response = AuthenticateResponse {
            code: 0,
            auth_token,
        };
        Ok(Response::new(response))
    }

    async fn add_password(
        &self,
        request: Request<AddPasswordRequest>,
    ) -> Result<Response<AddPasswordResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.user_id;
        let user_data = self.users.lock().unwrap().get_mut(&user_id).ok_or_else(|| {
            Status::not_found("User not found")
        })?;

        let auth_token_valid = todo!();
        if !auth_token_valid {
            return Err(Status::unauthenticated("Invalid auth token"));
        }

        let password_id = todo!() /* generate password ID */;
        let metadata = todo!() /* parse metadata */;
        let password_entry = PasswordEntry {
            ciphertext: req.ciphertext,
            metadata,
        };
        user_data.passwords.insert(password_id, password_entry);

        let response = AddPasswordResponse {
            metadata,
            code: 0,
            password_id,
        };
        Ok(Response::new(response))
    }

    async fn retrieve_password(
        &self,
        request: Request<RetrievePasswordRequest>,
    ) -> Result<Response<RetrievePasswordResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.user_id;
        let password_id = req.password_id;
        let user_data = self.users.lock().unwrap().get(&user_id).ok_or_else(|| {
            Status::not_found("User not found")
        })?;

        let password_entry = user_data.passwords.get(&password_id).ok_or_else(|| {
            Status::not_found("Password not found")
        })?;

        let response = RetrievePasswordResponse {
            ciphertext: password_entry.ciphertext.clone(),
            code: 0,
        };
        Ok(Response::new(response))
    }

    async fn delete_password(
        &self,
        request: Request<DeletePasswordRequest>,
    ) -> Result<Response<DeletePasswordResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.user_id;
        let password_id = req.password_id;
        let user_data = self.users.lock().unwrap().get_mut(&user_id).ok_or_else(|| {
            Status::not_found("User not found")
        })?;

        user_data.passwords.remove(&password_id);

        let response = DeletePasswordResponse { code: 0 };
        Ok(Response::new(response))
    }

    async fn update_password(
        &self,
        request: Request<UpdatePasswordRequest>,
    ) -> Result<Response<UpdatePasswordResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.user_id;
        let password_id = req.password_id;
        let user_data = self.users.lock().unwrap().get_mut(&user_id).ok_or_else(|| {
            Status::not_found("User not found")
        })?;

        let password_entry = user_data.passwords.get_mut(&password_id).ok_or_else(|| {
            Status::not_found("Password not found")
        })?;

        password_entry.ciphertext = req.ciphertext;

        let response = UpdatePasswordResponse { code: 0 };
        Ok(Response::new(response))
    }

    async fn list_passwords(
        &self,
        request: Request<ListPasswordsRequest>,
    ) -> Result<Response<ListPasswordsResponse>, Status> {
        let req = request.into_inner();
        let user_id = req.user_id;
        let user_data = self.users.lock().unwrap().get(&user_id).ok_or_else(|| {
            Status::not_found("User not found")
        })?;

        let metadata: Vec<_> = user_data
            .passwords
            .values()
            .map(|entry| entry.metadata.clone())
            .collect();

        let response = ListPasswordsResponse {
            metadata,
            code: 0,
        };
        Ok(Response::new(response))
    }
}


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

struct PasswordManagerDB {
    db: Arc<Mutex<Db>>,
}

impl PasswordManagerDB {
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
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
        let mut password_manager = PasswordManagerDB::new();

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
    } else if &s == "serv" {
        let addr = "[::1]:50051".parse().unwrap();
        let password_manager_service = PasswordManagerService::default();

        println!("PasswordManager server listening on {}", addr);

        tonic::transport::server::Server::builder()
            .add_service(PasswordManagerServer::new(password_manager_service))
            .serve(addr)
            .await?;
    } else {
        println!("\n Unknown option \nCurrent possible options : shards; password; homoc; db; auth; rotation; serv");
    }

    Ok(())
}

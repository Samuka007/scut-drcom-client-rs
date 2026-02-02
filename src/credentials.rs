/// Shared authentication credentials
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub hostname: String,
    pub hash: String,
}

impl Credentials {
    pub fn new(username: String, password: String, hostname: String, hash: String) -> Self {
        Self {
            username,
            password,
            hostname,
            hash,
        }
    }
}

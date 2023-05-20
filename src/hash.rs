use aes_gcm::aead::generic_array::GenericArray;
use sha3::{digest::OutputSizeUser, Digest, Sha3_256};
use std::collections::HashMap;

pub type HashFunction = dyn Fn(&[u8]) -> Vec<u8>;

pub struct HashFunctionRegistry {
    functions: HashMap<String, Box<HashFunction>>,
}

impl HashFunctionRegistry {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: &str, hash_fn: Box<HashFunction>) {
        self.functions.insert(name.to_owned(), Box::new(hash_fn));
    }

    pub fn get_function(&self, name: &str) -> &Box<HashFunction> {
        self.functions.get(name).unwrap()
    }

    pub fn get_names(&self) -> Vec<&String> {
        self.functions.keys().collect()
    }
}

impl Default for HashFunctionRegistry {
    fn default() -> Self {
        let mut registry = HashFunctionRegistry::new();
        registry.register("sha3-256", Box::new(sha3_256));
        registry
    }
}

fn sha3_256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result: GenericArray<u8, <Sha3_256 as OutputSizeUser>::OutputSize> = hasher.finalize();
    result.to_vec()
}

#[cfg(test)]
mod tests {
    use super::{sha3_256, HashFunctionRegistry};

    #[test]
    fn sha3_256_hash() {
        let data = b"Example dummy data";
        let result = sha3_256(data);
    }

    #[test]
    fn registry_hash() {
        let data = b"Example dummy data";
        let direct_result = sha3_256(data);
        let registry = HashFunctionRegistry::default();
        let hash = registry.get_function("sha3-256");
        let registry_result = hash(data);

        assert_eq!(direct_result, registry_result);
    }
}

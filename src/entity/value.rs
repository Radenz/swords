#[derive(Debug)]
pub struct Value {
    value: String,
    revealed_value: Option<String>,
    is_secret: bool,
}

pub const VALUE_STARTER_BYTE: u8 = 0x00;
pub const KEY_STARTER_BYTE: u8 = 0x00;
pub const SECRET_VALUE_STARTER_BYTE: u8 = 0x01;

impl Value {
    pub fn new(value: String, is_secret: bool) -> Self {
        Self {
            value,
            is_secret,
            revealed_value: None,
        }
    }

    pub fn take(self) -> String {
        self.value
    }

    pub fn is_secret(&self) -> bool {
        self.is_secret
    }
}

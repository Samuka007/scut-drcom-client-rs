#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Code {
    REQUEST = 1,
    RESPONSE = 2,
    SUCCESS = 3,
    FAILURE = 4,
    H3CDATA = 10,
    Unknown,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Type {
    IDENTITY = 1,
    NOTIFICATION = 2,
    MD5 = 4,
    AVAILABLE = 20,
    Allocated0x07 = 7,
    Allocated0x08 = 8,
    Unknown,
}

//! Contains types from `teaclave-types` crate (done to remove dependency on `teaclave-types`)
use serde::{Deserialize, Deserializer};

/// 256-bit hash
pub type SgxMeasurement = [u8; sgx_types::SGX_HASH_SIZE];

/// Measurement of the code and data in the enclave along with the enclave author's identity
#[derive(Debug, Deserialize, Copy, Clone, Eq, PartialEq)]
pub struct EnclaveMeasurement {
    /// 256-bit hash of the enclave author's public key. This serves as the identity of the enclave author. The result
    /// is that those enclaves which have been authenticated with the same key shall have the same value placed in
    /// `mr_signer`.
    #[serde(deserialize_with = "from_hex")]
    pub mr_signer: SgxMeasurement,
    /// A single 256-bit hash that identifies the code and initial data to be placed inside the enclave, the expected
    /// order and position in which they are to be placed, and the security properties of those pages. A change in any
    /// of these variables will result in a different measurement.
    #[serde(deserialize_with = "from_hex")]
    pub mr_enclave: SgxMeasurement,
}

impl EnclaveMeasurement {
    pub fn new(mr_enclave: SgxMeasurement, mr_signer: SgxMeasurement) -> Self {
        Self {
            mr_enclave,
            mr_signer,
        }
    }
}

/// Wrapper around enclave attributes. Currently, there is only on attribute, i.e., `measurement`
#[derive(Clone)]
pub struct EnclaveAttr {
    /// Measurement of the code and data in the enclave along with the enclave author's identity
    pub measurement: EnclaveMeasurement,
}

/// Deserializes a hex string to a `SgxMeasurement` (i.e., [0; 32]).
fn from_hex<'de, D>(deserializer: D) -> Result<SgxMeasurement, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        let v = hex::decode(&string).map_err(|_| Error::custom("ParseError"))?;
        let mut array = [0; sgx_types::SGX_HASH_SIZE];
        let bytes = &v[..array.len()]; // panics if not enough data
        array.copy_from_slice(bytes);
        Ok(array)
    })
}

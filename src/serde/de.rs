// SPDX-License-Idnetifier: Apache-2.0
use crate::{Multihash, mh::SIGIL};
use core::fmt;
use multi_codec::Codec;
use multi_util::EncodedVarbytes;
use serde::{
    Deserialize, Deserializer,
    de::{Error, MapAccess, Visitor},
};

/// Deserialize instance of [`crate::Multihash`]
impl<'de> Deserialize<'de> for Multihash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["codec", "hash"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Codec,
            Hash,
        }

        struct MultihashVisitor;

        impl<'de> Visitor<'de> for MultihashVisitor {
            type Value = Multihash;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "struct Multihash")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Multihash, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut codec = None;
                let mut hash = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Codec => {
                            if codec.is_some() {
                                return Err(Error::duplicate_field("codec"));
                            }
                            let s: &str = map.next_value()?;
                            codec = Some(
                                Codec::try_from(s)
                                    .map_err(|_| Error::custom("invalid multihash codec"))?,
                            );
                        }
                        Field::Hash => {
                            if hash.is_some() {
                                return Err(Error::duplicate_field("hash"));
                            }
                            let vb: EncodedVarbytes = map.next_value()?;
                            hash = Some(vb.to_inner().to_inner());
                        }
                    }
                }
                let codec = codec.ok_or_else(|| Error::missing_field("codec"))?;
                let hash = hash.ok_or_else(|| Error::missing_field("hash"))?;
                Ok(Multihash { codec, hash })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(SIGIL.as_str(), FIELDS, MultihashVisitor)
        } else {
            // Use `deserialize_byte_buf` with a visitor that accepts both
            // borrowed and owned bytes. This works with `serde_test`
            // (BorrowedBytes), `serde_cbor` (borrowed), and `ciborium`
            // (owned). The previous `&'de [u8]` bound only worked with
            // deserializers that support borrowing from input.
            struct ByteBufVisitor;

            impl<'de> Visitor<'de> for ByteBufVisitor {
                type Value = Vec<u8>;

                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("byte buffer")
                }

                fn visit_borrowed_bytes<E: Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
                    Ok(v.to_vec())
                }

                fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                    Ok(v.to_vec())
                }

                fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                    Ok(v)
                }
            }

            let b = deserializer.deserialize_byte_buf(ByteBufVisitor)?;
            Ok(Self::try_from(b.as_slice()).map_err(|e| Error::custom(e.to_string()))?)
        }
    }
}

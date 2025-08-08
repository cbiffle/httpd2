//! Logging support code.

/// Makes a key-value optional, so it can be tossed at a log record without
/// requiring conditional code.
pub struct OptionKV<T>(Option<T>);

impl<T> From<Option<T>> for OptionKV<T> {
    fn from(o: Option<T>) -> Self {
        OptionKV(o)
    }
}

impl<T: slog::KV> slog::KV for OptionKV<T> {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        match &self.0 {
            None => Ok(()),
            Some(kv) => kv.serialize(record, serializer),
        }
    }
}

//! URL percent-encoding decoder.
//!
//! This decoder interprets the standard somewhat loosely. Correctly encoded
//! paths are decoded just fine; errors, on the other hand, are literally passed
//! into the output. Since percent signs are not significant in paths, this is
//! safe.
//!
//! The decoder is expressed as an `Iterator`. Create one using
//! `decode`.

pub fn decode(inner: impl Iterator<Item = char>) -> impl Iterator<Item = char> {
    PercentDecoder::from(inner)
}

struct PercentDecoder<I> {
    inner: I,
    state: PercentState,
}

impl<I> From<I> for PercentDecoder<I> {
    fn from(inner: I) -> Self {
        Self {
            inner,
            state: PercentState::Normal,
        }
    }
}

enum PercentState {
    /// Haven't seen a percent escape recently.
    Normal,
    /// A percent escape was found to be invalid on its final character. We have
    /// yielded the original '%' and need to yield these additional characters
    /// in sequence before touching `inner`.
    Unspool2(char, char),
    /// A percent escape was found to be invalid. We have yielded some portion
    /// of it literally, and still need to yield this char before touching
    /// `inner`.
    Unspool(char),
}

impl<I: Iterator<Item = char>> Iterator for PercentDecoder<I> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        fn hexit(c: char) -> Option<u8> {
            match c {
                '0'..='9' => Some(c as u8 - b'0'),
                'A'..='F' => Some(c as u8 - b'A' + 10),
                'a'..='f' => Some(c as u8 - b'a' + 10),
                _ => None,
            }
        }

        match self.state {
            PercentState::Normal => match self.inner.next()? {
                '%' => {
                    if let Some(x) = self.inner.next() {
                        if let Some(y) = self.inner.next() {
                            if let (Some(x), Some(y)) = (hexit(x), hexit(y)) {
                                return Some((x << 4 | y) as char);
                            }
                            self.state = PercentState::Unspool2(x, y);
                        } else {
                            self.state = PercentState::Unspool(x);
                        }
                    }
                    Some('%')
                }
                c => Some(c),
            },
            PercentState::Unspool2(x, y) => {
                self.state = PercentState::Unspool(y);
                Some(x)
            }
            PercentState::Unspool(y) => {
                self.state = PercentState::Normal;
                Some(y)
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (min, max) = self.inner.size_hint();
        (min / 3, max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_str(s: &str) -> String {
        decode(s.chars()).collect()
    }

    #[test]
    fn percent_decode() {
        assert_eq!(decode_str(""), "");
        assert_eq!(decode_str("%"), "%");
        assert_eq!(decode_str("%%%"), "%%%");
        assert_eq!(decode_str("%4"), "%4");
        assert_eq!(decode_str("%41"), "A");
        assert_eq!(decode_str("%4a"), "J");
        assert_eq!(decode_str("%4A"), "J");
        assert_eq!(decode_str("%4g"), "%4g");
        assert_eq!(decode_str("%2525"), "%25");
    }
}

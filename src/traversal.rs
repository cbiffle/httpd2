//! Filesystem traversal sanitizer.
//!
//! This module uses a derivative of the sanitization algorithm used by
//! publicfile. A sanitized path...
//!
//! - Is relative (begins with `"./"`).
//! - Contains no NUL characters, as this would confuse the operating system.
//! - Contains no repeated slashes.
//! - Contains no `"/."` sequences, preventing access to parent directories and
//!   dotfiles.
//!
//! The sanitizer API is an `Iterator`. Use `sanitize` to get one.
//!
//! Note that path sanitization should be applied *last*, after any other decode
//! steps, immediately before passing the path to the OS.

/// Adapts `inner` to sanitize path names.
pub fn sanitize(inner: impl Iterator<Item = char>) -> impl Iterator<Item = char> {
    Sanitizer::from(inner)
}

struct Sanitizer<I> {
    inner: I,
    state: SanitizerState,
}

impl<I> From<I> for Sanitizer<I> {
    fn from(inner: I) -> Self {
        Self { inner, state: SanitizerState::EmitDot }
    }
}

#[derive(Copy, Clone, Debug)]
enum SanitizerState {
    EmitDot,
    EmitSlash,
    Normal,
    Slash,
}

impl<I: Iterator<Item = char>> Iterator for Sanitizer<I> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            SanitizerState::EmitDot => {
                self.state = SanitizerState::EmitSlash;
                return Some('.')
            }
            SanitizerState::EmitSlash => {
                self.state = SanitizerState::Slash;
                return Some('/')
            }
            _ => (),
        }

        loop {
            match (self.state, self.inner.next()?) {
                (_, '\0') => {
                    self.state = SanitizerState::Normal;
                    break Some('_')
                }
                (SanitizerState::Normal, '/') => {
                    self.state = SanitizerState::Slash;
                    break Some('/')
                }
                (SanitizerState::Slash, '/') => continue,
                (SanitizerState::Slash, '.') => {
                    self.state = SanitizerState::Normal;
                    break Some(':')
                }
                (_, c) => {
                    self.state = SanitizerState::Normal;
                    break Some(c)
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // We alter the inner size-hint because it's possible that we discard
        // all characters. The max length is extended by the initial dot-slash.
        (0, self.inner.size_hint().1.map(|x| x + 2))
    }
}



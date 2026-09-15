//! Terminfo parameter expansion.
//!
//! A parameterised capability is a small program, not a template: it pushes parameters, does
//! arithmetic on them and branches. The class-coverage check has to know what a capability really
//! produces, so it runs that program here with representative arguments rather than comparing
//! against a sequence someone wrote out by hand. A hand-written sample can drift from the value it
//! claims to illustrate, and a sample that drifts proves the wrong thing.

/// One argument to a parameterised capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Param {
    /// A numeric parameter.
    Number(i32),
    /// A string parameter.
    Text(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Number(i32),
    Text(String),
}

impl Value {
    fn number(&self) -> i32 {
        match self {
            Self::Number(value) => *value,
            Self::Text(text) => text.len() as i32,
        }
    }

    fn text(&self) -> String {
        match self {
            Self::Number(value) => value.to_string(),
            Self::Text(text) => text.clone(),
        }
    }
}

/// Runs `value` with `params` and returns the bytes it produces.
///
/// Unknown directives and pops from an empty stack follow the usual terminfo behaviour: the pop
/// yields zero and the program keeps going, because a capability database is data and a malformed
/// entry must not stop the check that exists to find it.
#[must_use]
pub fn expand(value: &str, params: &[Param]) -> Vec<u8> {
    Machine::new(params).run(value.as_bytes())
}

struct Machine {
    stack: Vec<Value>,
    params: Vec<Value>,
    dynamic: Vec<Value>,
    statics: Vec<Value>,
    out: Vec<u8>,
}

impl Machine {
    fn new(params: &[Param]) -> Self {
        let params = params
            .iter()
            .map(|param| match param {
                Param::Number(value) => Value::Number(*value),
                Param::Text(text) => Value::Text((*text).to_owned()),
            })
            .collect();
        Self {
            stack: Vec::new(),
            params,
            dynamic: vec![Value::Number(0); 26],
            statics: vec![Value::Number(0); 26],
            out: Vec::new(),
        }
    }

    fn pop(&mut self) -> Value {
        self.stack.pop().unwrap_or(Value::Number(0))
    }

    fn pop_number(&mut self) -> i32 {
        self.pop().number()
    }

    fn binary(&mut self, op: impl Fn(i32, i32) -> i32) {
        let right = self.pop_number();
        let left = self.pop_number();
        self.stack.push(Value::Number(op(left, right)));
    }

    fn run(mut self, program: &[u8]) -> Vec<u8> {
        let mut index = 0;
        while index < program.len() {
            if program[index] != b'%' {
                self.out.push(program[index]);
                index += 1;
                continue;
            }
            index += 1;
            let Some(&directive) = program.get(index) else {
                break;
            };
            index += 1;
            match directive {
                b'%' => self.out.push(b'%'),
                b'c'
                | b'd'
                | b'o'
                | b's'
                | b'x'
                | b'X'
                | b'u'
                | b':'
                | b'+'
                | b'-'
                | b'#'
                | b' '
                | b'.'
                | b'0'..=b'9'
                    if is_format(program, index - 1) =>
                {
                    index = self.format(program, index - 1);
                }
                b'p' => {
                    let slot = program.get(index).copied().unwrap_or(b'1');
                    index += 1;
                    let slot = usize::from(slot.saturating_sub(b'1'));
                    let value = self.params.get(slot).cloned().unwrap_or(Value::Number(0));
                    self.stack.push(value);
                }
                b'P' => {
                    let name = program.get(index).copied().unwrap_or(b'a');
                    index += 1;
                    let value = self.pop();
                    if let Some(slot) = slot_of(name) {
                        if name.is_ascii_lowercase() {
                            self.dynamic[slot] = value;
                        } else {
                            self.statics[slot] = value;
                        }
                    }
                }
                b'g' => {
                    let name = program.get(index).copied().unwrap_or(b'a');
                    index += 1;
                    if let Some(slot) = slot_of(name) {
                        let value = if name.is_ascii_lowercase() {
                            self.dynamic[slot].clone()
                        } else {
                            self.statics[slot].clone()
                        };
                        self.stack.push(value);
                    }
                }
                b'\'' => {
                    let value = program.get(index).copied().unwrap_or(0);
                    // Step over the character and its closing quote.
                    index += 2;
                    self.stack.push(Value::Number(i32::from(value)));
                }
                b'{' => {
                    let mut number = 0i32;
                    let mut negative = false;
                    if program.get(index) == Some(&b'-') {
                        negative = true;
                        index += 1;
                    }
                    while let Some(byte) = program.get(index) {
                        if !byte.is_ascii_digit() {
                            break;
                        }
                        number = number
                            .saturating_mul(10)
                            .saturating_add(i32::from(byte - b'0'));
                        index += 1;
                    }
                    if program.get(index) == Some(&b'}') {
                        index += 1;
                    }
                    self.stack
                        .push(Value::Number(if negative { -number } else { number }));
                }
                b'l' => {
                    let value = self.pop();
                    self.stack.push(Value::Number(value.text().len() as i32));
                }
                b'i' => {
                    for slot in 0..2 {
                        if let Some(Value::Number(value)) = self.params.get(slot) {
                            self.params[slot] = Value::Number(value.saturating_add(1));
                        }
                    }
                }
                b'+' => self.binary(i32::saturating_add),
                b'-' => self.binary(i32::saturating_sub),
                b'*' => self.binary(i32::saturating_mul),
                b'/' => self.binary(|left, right| if right == 0 { 0 } else { left / right }),
                b'm' => self.binary(|left, right| if right == 0 { 0 } else { left % right }),
                b'&' => self.binary(|left, right| left & right),
                b'|' => self.binary(|left, right| left | right),
                b'^' => self.binary(|left, right| left ^ right),
                b'=' => self.binary(|left, right| i32::from(left == right)),
                b'<' => self.binary(|left, right| i32::from(left < right)),
                b'>' => self.binary(|left, right| i32::from(left > right)),
                b'A' => self.binary(|left, right| i32::from(left != 0 && right != 0)),
                b'O' => self.binary(|left, right| i32::from(left != 0 || right != 0)),
                b'!' => {
                    let value = self.pop_number();
                    self.stack.push(Value::Number(i32::from(value == 0)));
                }
                b'~' => {
                    let value = self.pop_number();
                    self.stack.push(Value::Number(!value));
                }
                b'?' | b';' => {}
                b't' => {
                    if self.pop_number() == 0 {
                        index = skip_branch(program, index);
                    }
                }
                b'e' => index = skip_to_end(program, index),
                _ => {}
            }
        }
        self.out
    }

    /// Formats the top of the stack, returning the index after the directive.
    fn format(&mut self, program: &[u8], start: usize) -> usize {
        let mut index = start;
        let mut left_align = false;
        let mut zero_pad = false;
        let mut alternate = false;
        let mut sign = false;
        let mut width = 0usize;
        let mut precision = 0usize;
        while let Some(&byte) = program.get(index) {
            match byte {
                b':' => {}
                b'-' => left_align = true,
                b'+' => sign = true,
                b'#' => alternate = true,
                b' ' => {}
                _ => break,
            }
            index += 1;
        }
        while let Some(byte) = program.get(index) {
            if !byte.is_ascii_digit() {
                break;
            }
            if width == 0 && *byte == b'0' {
                zero_pad = true;
            }
            width = width * 10 + usize::from(byte - b'0');
            index += 1;
        }
        if program.get(index) == Some(&b'.') {
            index += 1;
            while let Some(byte) = program.get(index) {
                if !byte.is_ascii_digit() {
                    break;
                }
                precision = precision * 10 + usize::from(byte - b'0');
                index += 1;
            }
        }
        let Some(&conversion) = program.get(index) else {
            return index;
        };
        index += 1;
        let mut text = match conversion {
            b'c' => {
                let value = self.pop_number();
                let byte = u8::try_from(value).unwrap_or(0);
                String::from_utf8_lossy(&[byte]).into_owned()
            }
            b's' => self.pop().text(),
            b'd' | b'u' => {
                let value = self.pop_number();
                let mut text = value.abs().to_string();
                while text.len() < precision {
                    text.insert(0, '0');
                }
                if value < 0 {
                    text.insert(0, '-');
                } else if sign {
                    text.insert(0, '+');
                }
                text
            }
            b'o' => digits(self.pop_number(), 8, false, precision, alternate),
            b'x' => digits(self.pop_number(), 16, false, precision, alternate),
            b'X' => digits(self.pop_number(), 16, true, precision, alternate),
            _ => String::new(),
        };
        while text.len() < width {
            if left_align {
                text.push(' ');
            } else if zero_pad {
                text.insert(0, '0');
            } else {
                text.insert(0, ' ');
            }
        }
        self.out.extend_from_slice(text.as_bytes());
        index
    }
}

/// Whether the directive at `index` opens a printf-style conversion.
///
/// The arithmetic operators share their spelling with printf flags, so a `%-` is a subtraction
/// unless a conversion letter follows it.
fn is_format(program: &[u8], index: usize) -> bool {
    let mut index = index;
    while let Some(&byte) = program.get(index) {
        match byte {
            b':' | b'-' | b'+' | b'#' | b' ' | b'.' | b'0'..=b'9' => index += 1,
            b'c' | b'd' | b'o' | b's' | b'x' | b'X' | b'u' => return true,
            _ => return false,
        }
    }
    false
}

fn slot_of(name: u8) -> Option<usize> {
    if name.is_ascii_lowercase() {
        Some(usize::from(name - b'a'))
    } else if name.is_ascii_uppercase() {
        Some(usize::from(name - b'A'))
    } else {
        None
    }
}

fn digits(value: i32, radix: u32, upper: bool, precision: usize, alternate: bool) -> String {
    #[expect(
        clippy::cast_sign_loss,
        reason = "terminfo formats a negative value as its two's-complement digits, as printf does"
    )]
    let unsigned = value as u32;
    let mut text = match radix {
        8 => format!("{unsigned:o}"),
        _ if upper => format!("{unsigned:X}"),
        _ => format!("{unsigned:x}"),
    };
    while text.len() < precision {
        text.insert(0, '0');
    }
    if alternate && value != 0 {
        text.insert_str(0, if radix == 8 { "0" } else { "0x" });
    }
    text
}

/// Moves past the branch a false condition skips, to just after its `%e` or `%;`.
fn skip_branch(program: &[u8], index: usize) -> usize {
    let mut index = index;
    let mut depth = 0usize;
    while index < program.len() {
        if program[index] != b'%' {
            index += 1;
            continue;
        }
        let Some(&directive) = program.get(index + 1) else {
            return program.len();
        };
        match directive {
            b'?' => depth += 1,
            b';' if depth == 0 => return index + 2,
            b';' => depth -= 1,
            b'e' if depth == 0 => return index + 2,
            _ => {}
        }
        index += 2;
    }
    index
}

/// Moves past the rest of a taken branch, to just after its `%;`.
fn skip_to_end(program: &[u8], index: usize) -> usize {
    let mut index = index;
    let mut depth = 0usize;
    while index < program.len() {
        if program[index] != b'%' {
            index += 1;
            continue;
        }
        let Some(&directive) = program.get(index + 1) else {
            return program.len();
        };
        match directive {
            b'?' => depth += 1,
            b';' if depth == 0 => return index + 2,
            b';' => depth -= 1,
            _ => {}
        }
        index += 2;
    }
    index
}

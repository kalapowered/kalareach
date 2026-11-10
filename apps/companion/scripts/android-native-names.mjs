// Reads which of the application's Java classes a packaged native library finds by name.
//
// Native code reaches Java by name: it asks the runtime for a class by its name, binds the native
// methods a class declares by the symbols it exports, and describes a method by the names of the
// classes in its signature. A minifier that renames or removes a class that only native code
// reaches leaves the library loadable and the application dead at the first call: the runtime
// aborts the process when the library's start-up asks for a class that is not there.
//
// So the library is read for the names it carries, and two things in it are exact. Its exported
// `Java_` symbols name the class and the method each native method is bound to. And its strings name
// classes in three forms: a type descriptor (`Lorg/webrtc/IceCandidate;`), which ends at its
// semicolon, and a name that a C string ends with a NUL, either dotted (`org.jni_zero.JniZero`, as
// a class loader takes it) or with slashes (`org/webrtc/IceCandidate`, as `FindClass` takes it). A
// string that only runs into the next one, as Rust packs its literals, has no end to read, so only
// descriptors and NUL-ended names count.
//
// A name is a class's when it has the shape of one: packages in lower case, at least two of them,
// and a class that starts with a capital letter, with its nested classes after `$`. That leaves out
// the library's file names, its metric names (`WebRTC.Video.Encoder.CodecType`) and its short
// symbol-like strings, none of which the application defines. Classes the platform supplies are
// left out as well.
/** The classes the platform supplies, which no package is asked to define. */
const PLATFORM =
  /^(?:java|javax|android|dalvik|libcore|sun|jdk|com\.android|org\.(?:json|w3c|xml|xmlpull))\./

const PACKAGE = '[a-z][a-z0-9_]*'
const CLASS = '[A-Z][A-Za-z0-9_]*(?:\\$[A-Za-z0-9_$]+)*'
/** Not the middle of a longer name, or of a word or a path that joins one with a hyphen. */
const NOT_NAME = '(?<![A-Za-z0-9_$./-])'
/**
 * What may come before the `L` of a class in a descriptor: the start of the list, the end of a
 * type, an array's mark or a primitive type's letter.
 */
const BEFORE_CLASS = '(?<=^|[()\\[;IJZBCSFDV\\0])'

const DOTTED = new RegExp(`${NOT_NAME}(${PACKAGE}(?:\\.${PACKAGE})+\\.${CLASS})(?=\\0)`, 'g')
const SLASHED = new RegExp(`${NOT_NAME}(${PACKAGE}(?:/${PACKAGE})+/${CLASS})(?=\\0)`, 'g')
const DESCRIPTOR = new RegExp(`${BEFORE_CLASS}L(${PACKAGE}(?:/${PACKAGE})+/${CLASS});`, 'g')

/**
 * The classes of the application a library's strings name, in source form (`a.b.C`).
 *
 * The bytes are read as Latin-1, which keeps every byte one character and so keeps the NUL that ends
 * a C string.
 */
export function libraryClassNames(bytes) {
  const text = bytes.toString('latin1')
  const names = new Set()
  for (const pattern of [DOTTED, SLASHED, DESCRIPTOR]) {
    for (const match of text.matchAll(pattern)) {
      const name = match[1].replaceAll('/', '.')
      if (!PLATFORM.test(name)) names.add(name)
    }
  }
  return names
}

// -- the exported symbols ---------------------------------------------------------------------------

const SHT_DYNSYM = 11
const SHN_UNDEF = 0

/** Reads an unsigned 64-bit field as a number: no library here is near 2^53 bytes. */
function u64(bytes, at) {
  return Number(bytes.readBigUInt64LE(at))
}

/**
 * The names of the symbols a shared library defines for others to find, from its dynamic symbol
 * table. Refuses a file that is not an ELF library of either width in the byte order Android runs.
 */
function exportedSymbols(bytes) {
  if (bytes.length < 52 || bytes.readUInt32BE(0) !== 0x7f454c46) throw new Error('not an ELF library')
  const wide = bytes[4] === 2
  if ((bytes[4] !== 1 && bytes[4] !== 2) || bytes[5] !== 1) {
    throw new Error('an ELF library of a layout this does not read')
  }
  const tableAt = wide ? u64(bytes, 0x28) : bytes.readUInt32LE(0x20)
  const entrySize = bytes.readUInt16LE(wide ? 0x3a : 0x2e)
  const count = bytes.readUInt16LE(wide ? 0x3c : 0x30)
  if (tableAt === 0 || count === 0 || tableAt + count * entrySize > bytes.length) return []
  const section = (index) => {
    const at = tableAt + index * entrySize
    return wide
      ? {
          type: bytes.readUInt32LE(at + 4),
          offset: u64(bytes, at + 0x18),
          size: u64(bytes, at + 0x20),
          link: bytes.readUInt32LE(at + 0x28)
        }
      : {
          type: bytes.readUInt32LE(at + 4),
          offset: bytes.readUInt32LE(at + 0x10),
          size: bytes.readUInt32LE(at + 0x14),
          link: bytes.readUInt32LE(at + 0x18)
        }
  }
  const symbolSize = wide ? 24 : 16
  const names = []
  for (let index = 0; index < count; index += 1) {
    const symbols = section(index)
    if (symbols.type !== SHT_DYNSYM) continue
    const strings = section(symbols.link)
    for (let at = symbols.offset; at + symbolSize <= symbols.offset + symbols.size; at += symbolSize) {
      const shndx = bytes.readUInt16LE(at + (wide ? 6 : 14))
      if (shndx === SHN_UNDEF) continue
      const start = strings.offset + bytes.readUInt32LE(at)
      names.push(bytes.subarray(start, bytes.indexOf(0, start)).toString('latin1'))
    }
  }
  return names
}

/**
 * The class and method a `Java_` symbol is bound to, or null when the symbol is no native method's.
 *
 * The runtime's mangling writes the package and class separators as `_`, a literal underscore as
 * `_1`, `;` as `_2`, `[` as `_3` and any other character as `_0` and four hex digits; an overloaded
 * method continues with `__` and its mangled signature.
 */
export function nativeMethodOf(symbol) {
  if (!symbol.startsWith('Java_')) return null
  const mangled = symbol.slice(5)
  const parts = ['']
  for (let at = 0; at < mangled.length; at += 1) {
    const char = mangled[at]
    if (char !== '_') {
      parts[parts.length - 1] += char
      continue
    }
    const next = mangled[at + 1]
    if (next === '1' || next === '2' || next === '3') {
      parts[parts.length - 1] += { 1: '_', 2: ';', 3: '[' }[next]
      at += 1
    } else if (next === '0' && /^[0-9a-fA-F]{4}$/.test(mangled.slice(at + 2, at + 6))) {
      parts[parts.length - 1] += String.fromCharCode(parseInt(mangled.slice(at + 2, at + 6), 16))
      at += 5
    } else if (next === '_' && !/[0-3]/.test(mangled[at + 2] ?? '')) {
      // The signature of an overloaded method follows; the name is what came before.
      break
    } else parts.push('')
  }
  if (parts.length < 2 || parts.some((part) => part === '')) return null
  return { cls: parts.slice(0, -1).join('.'), method: parts[parts.length - 1] }
}

/** The native methods a library is bound to by name: each exported `Java_` symbol, decoded. */
export function libraryNatives(bytes) {
  const natives = []
  for (const symbol of exportedSymbols(bytes)) {
    const bound = nativeMethodOf(symbol)
    if (bound) natives.push({ symbol, ...bound })
  }
  return natives
}

// The smallest archives that exercise the readers in this directory, built in memory for the
// self-tests: a dex that carries its string, type, method and class tables and nothing else, a
// shared library that carries its dynamic symbols and whatever bytes a case puts in it, and a
// stored zip. They are not archives any runtime would accept.
import { Buffer } from 'node:buffer'
import { crc32, deflateRawSync } from 'node:zlib'

/** A uleb128 of a small value. */
export function uleb(value) {
  const bytes = []
  do {
    let byte = value & 0x7f
    value >>>= 7
    if (value > 0) byte |= 0x80
    bytes.push(byte)
  } while (value > 0)
  return Buffer.from(bytes)
}

/**
 * A string as a dex file holds it: in modified UTF-8, which writes each UTF-16 unit on its own, so
 * that a character outside the basic plane is two three-byte groups, and writes the NUL as two bytes.
 */
export function modifiedUtf8(text) {
  const bytes = []
  for (let at = 0; at < text.length; at += 1) {
    const unit = text.charCodeAt(at)
    if (unit !== 0 && unit < 0x80) bytes.push(unit)
    else if (unit < 0x800) bytes.push(0xc0 | (unit >> 6), 0x80 | (unit & 0x3f))
    else bytes.push(0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3f), 0x80 | (unit & 0x3f))
  }
  return Buffer.from(bytes)
}

/**
 * A dex file that defines `defined` and names `referenced` without defining it.
 *
 * Both sets reach the string table, which is the point: a reader that searched the strings for a
 * class name could not tell a definition from a mention, and the application would pass a check
 * it should fail. Only `defined` reaches `class_defs`.
 *
 * The three tables are deliberately out of step with one another -- the strings run in one order
 * behind entries that are not class names at all, the type table points into them in another, and
 * `class_defs` points into the type table in a third -- so that a reader that took any one index
 * for any other would answer wrongly here.
 *
 * `constants` are strings the code carries that are no class's name, which sit in the string table
 * and nowhere else.
 *
 * `methods` gives a defined class its declared methods, `{ 'a.b.C': [{ name, native, static, params }] }`:
 * a static one goes in the class's list of direct methods and any other in its virtual methods, a
 * native one carries the native access flag, and `params` are its argument types as descriptors
 * (`['I', 'Ljava/lang/String;']`). The method table lists them in the opposite order to the classes,
 * so that a reader that took a method's place in a class for its place in the file would answer
 * wrongly. `fields` gives a class that many static and instance fields, `{ 'a.b.C': [1, 2] }`, which
 * come before its methods in its data and which a reader has to step over. `callSites` and
 * `methodHandles` make the map list say the file has that many call sites and method handles.
 */
export function dex({
  defined = [],
  referenced = [],
  constants = [],
  methods = {},
  fields = {},
  callSites = 0,
  methodHandles = 0
} = {}) {
  const descriptorOf = (name) => `L${name.replaceAll('.', '/')};`
  // Every class the file names. The superclass every real class has comes first, and the merely
  // mentioned ones next, so a class_defs index is never the type index it holds.
  const types = ['java.lang.Object', ...referenced, ...defined].map(descriptorOf)
  // The primitive types that the methods' prototypes name: a return type, and each argument type.
  const declared = Object.values(methods).flat()
  const primitives =
    declared.length === 0 ? [] : ['V', ...new Set(declared.flatMap((method) => method.params ?? []))]
  types.push(...primitives.filter((descriptor) => !types.includes(descriptor)))
  // A real string table holds method and field names as well as class names. Enough of them come
  // first here that a descriptor's string index is never its type index, and the descriptors
  // behind them run in the opposite order to the type table.
  const methodNames = [...new Set(Object.values(methods).flat().map((method) => method.name))]
  const strings = [
    ...types.map((_, index) => `member${index}`),
    ...constants,
    ...methodNames,
    ...[...types].reverse()
  ]
  const typeStringIndex = types.map((descriptor) => strings.indexOf(descriptor))
  const definedTypeIndex = defined.map((name) => types.indexOf(descriptorOf(name)))
  typeStringIndex.forEach((stringIndex, typeIndex) => {
    if (stringIndex === typeIndex) throw new Error('this fixture lines up two of its tables')
  })
  definedTypeIndex.forEach((typeIndex, classIndex) => {
    if (typeIndex === classIndex) throw new Error('this fixture lines up two of its tables')
  })

  // The method table, with the classes taken in reverse so that a class's methods are not where its
  // place in the class table would put them.
  const methodTable = []
  const methodIndexOf = new Map()
  const protos = []
  for (const name of [...defined].reverse()) {
    for (const method of methods[name] ?? []) {
      const params = method.params ?? []
      let proto = protos.findIndex((each) => each.join('|') === params.join('|'))
      if (proto < 0) proto = protos.push(params) - 1
      methodIndexOf.set(method, methodTable.length)
      methodTable.push({
        type: types.indexOf(descriptorOf(name)),
        proto,
        name: strings.indexOf(method.name)
      })
    }
  }

  const header = Buffer.alloc(112)
  header.write('dex\n035\0', 0, 'latin1')
  const stringIdsAt = 112
  const typeIdsAt = stringIdsAt + strings.length * 4
  const protoIdsAt = typeIdsAt + types.length * 4
  const methodIdsAt = protoIdsAt + protos.length * 12
  const classDefsAt = methodIdsAt + methodTable.length * 8
  const dataAt = classDefsAt + definedTypeIndex.length * 32
  header.writeUInt32LE(strings.length, 0x38)
  header.writeUInt32LE(stringIdsAt, 0x3c)
  header.writeUInt32LE(types.length, 0x40)
  header.writeUInt32LE(typeIdsAt, 0x44)
  header.writeUInt32LE(protos.length, 0x48)
  header.writeUInt32LE(protoIdsAt, 0x4c)
  header.writeUInt32LE(methodTable.length, 0x58)
  header.writeUInt32LE(methodIdsAt, 0x5c)
  header.writeUInt32LE(definedTypeIndex.length, 0x60)
  header.writeUInt32LE(classDefsAt, 0x64)

  const stringIds = Buffer.alloc(strings.length * 4)
  const typeIds = Buffer.alloc(types.length * 4)
  const classDefs = Buffer.alloc(definedTypeIndex.length * 32)
  const data = []
  let at = dataAt
  // The map list, which names the sections of the file: a header item, and a call-site or method-handle
  // item when `callSites` or `methodHandles` says the file has that table (it is not written). It is
  // first in the data section here, so that the item a case changes at the file's end stays there.
  const mapItems = [[0x0000, 1]]
  if (callSites > 0) mapItems.push([0x0007, callSites])
  if (methodHandles > 0) mapItems.push([0x0008, methodHandles])
  const map = Buffer.alloc(4 + mapItems.length * 12)
  map.writeUInt32LE(mapItems.length, 0)
  mapItems.forEach(([type, size], index) => {
    map.writeUInt16LE(type, 4 + index * 12)
    map.writeUInt32LE(size, 8 + index * 12)
  })
  header.writeUInt32LE(at, 0x34)
  data.push(map)
  at += map.length
  strings.forEach((text, index) => {
    stringIds.writeUInt32LE(at, index * 4)
    const item = Buffer.concat([uleb(text.length), modifiedUtf8(text), Buffer.from([0])])
    data.push(item)
    at += item.length
  })
  typeStringIndex.forEach((stringIndex, index) => typeIds.writeUInt32LE(stringIndex, index * 4))
  // The prototypes: a return type of void, and the argument types as a list in the data.
  const protoIds = Buffer.alloc(protos.length * 12)
  protos.forEach((params, index) => {
    protoIds.writeUInt32LE(types.indexOf('V'), index * 12 + 4)
    if (params.length === 0) return
    const list = Buffer.alloc(4 + params.length * 2)
    list.writeUInt32LE(params.length, 0)
    params.forEach((descriptor, each) => list.writeUInt16LE(types.indexOf(descriptor), 4 + each * 2))
    protoIds.writeUInt32LE(at, index * 12 + 8)
    data.push(list)
    at += list.length
  })
  const methodIds = Buffer.alloc(methodTable.length * 8)
  methodTable.forEach((entry, index) => {
    methodIds.writeUInt16LE(entry.type, index * 8)
    methodIds.writeUInt16LE(entry.proto, index * 8 + 2)
    methodIds.writeUInt32LE(entry.name, index * 8 + 4)
  })
  definedTypeIndex.forEach((typeIndex, index) => {
    classDefs.writeUInt32LE(typeIndex, index * 32)
    const own = methods[defined[index]] ?? []
    const [staticFields, instanceFields] = fields[defined[index]] ?? [0, 0]
    if (own.length === 0 && staticFields + instanceFields === 0) return
    // A class's data item: the four counts, then the fields, then each list of methods in ascending
    // table order, as the difference from the one before.
    const list = (declared) =>
      declared
        .map((method) => ({ method, index: methodIndexOf.get(method) }))
        .sort((a, b) => a.index - b.index)
        .flatMap((entry, place, all) => {
          const flags = 0x1 | (entry.method.static ? 0x8 : 0) | (entry.method.native ? 0x100 : 0)
          // A method's code item is not written; its offset is 0 unless a case gives one (`'inside'` is
          // a place in the data section).
          const code = entry.method.code === 'inside' ? dataAt : (entry.method.code ?? 0)
          return [uleb(entry.index - (place === 0 ? 0 : all[place - 1].index)), uleb(flags), uleb(code)]
        })
    const direct = own.filter((method) => method.static)
    const virtual = own.filter((method) => !method.static)
    const fieldEntries = Array.from({ length: staticFields + instanceFields }, () => [uleb(1), uleb(0x19)])
    const item = Buffer.concat([
      uleb(staticFields),
      uleb(instanceFields),
      uleb(direct.length),
      uleb(virtual.length),
      ...fieldEntries.flat(),
      ...list(direct),
      ...list(virtual)
    ])
    classDefs.writeUInt32LE(at, index * 32 + 24)
    data.push(item)
    at += item.length
  })
  // The data section, which every offset of the string data, type lists, class data and code lies in.
  header.writeUInt32LE(at - dataAt, 0x68)
  header.writeUInt32LE(dataAt, 0x6c)
  return Buffer.concat([header, stringIds, typeIds, protoIds, methodIds, classDefs, ...data])
}

/**
 * A shared library that defines the symbols `exports` names, refers to the ones `imports` names
 * without defining them, and carries `blobs` (buffers, placed as given) in between.
 *
 * It has what the reader of dynamic symbols looks at -- the ELF header, a dynamic symbol table with
 * its string table and the section headers that find them -- and no code. `wide` is a 64-bit
 * library, as the ABIs the application ships are, and not wide a 32-bit one. `locals` and `hidden`
 * name defined symbols that are local and that are hidden, which no other library can find, and
 * `weak` ones that are weak, which it can. `headers: false` leaves the section headers out,
 * `dynamic: false` makes the symbol table an ordinary one, and `stringsLink` is the section the
 * symbol table names as its strings (1 is the string table, 3 the table of section names).
 *
 * The rest make the tables wrong in one way each: `entsize` is the entry size the symbol table's
 * header gives (its own, by default), `tail` bytes follow the last symbol and are counted in the
 * table's size, `nameBeyond` puts the first exported symbol's name past the end of the string table,
 * `unterminated` cuts the NUL off the end of the string table's last name, and `emptySymbols` leaves
 * the symbol table with no bytes at all, not even the reserved first entry.
 */
export function elf({
  exports = [],
  imports = [],
  locals = [],
  hidden = [],
  weak = [],
  blobs = [],
  wide = true,
  headers = true,
  dynamic = true,
  stringsLink = 1,
  entsize = null,
  tail = Buffer.alloc(0),
  nameBeyond = false,
  unterminated = false,
  emptySymbols = false
} = {}) {
  const sectionNames = ['', '.dynstr', '.dynsym', '.shstrtab']
  const text = (names) => {
    const offsets = new Map()
    const parts = [Buffer.from([0])]
    let at = 1
    for (const name of names) {
      if (name === '') continue
      offsets.set(name, at)
      const bytes = Buffer.from(`${name}\0`, 'latin1')
      parts.push(bytes)
      at += bytes.length
    }
    return { offsets, bytes: Buffer.concat(parts) }
  }
  const names = text([...imports, ...exports, ...locals, ...hidden, ...weak])
  // The string table as the file carries it: the last name loses its NUL when a case asks.
  const dynstr = { offsets: names.offsets, bytes: unterminated ? names.bytes.subarray(0, -1) : names.bytes }
  const shstr = text(sectionNames)
  const symbolSize = wide ? 24 : 16
  const symbols = [
    ...imports.map((name) => [name, 0, 0x12, 0]),
    ...exports.map((name) => [name, 1, 0x12, 0]),
    ...locals.map((name) => [name, 1, 0x02, 0]),
    ...hidden.map((name) => [name, 1, 0x12, 2]),
    ...weak.map((name) => [name, 1, 0x22, 0])
  ]
  const dynsym = emptySymbols
    ? Buffer.alloc(0)
    : Buffer.concat([Buffer.alloc((1 + symbols.length) * symbolSize), tail])
  symbols.forEach(([name, section, info, other], index) => {
    const at = (index + 1) * symbolSize
    const beyond = nameBeyond && name === exports[0]
    dynsym.writeUInt32LE(beyond ? dynstr.bytes.length + 100 : dynstr.offsets.get(name), at)
    dynsym.writeUInt8(info, at + (wide ? 4 : 12))
    dynsym.writeUInt8(other, at + (wide ? 5 : 13))
    dynsym.writeUInt16LE(section, at + (wide ? 6 : 14))
  })
  const headerSize = wide ? 64 : 52
  const sectionSize = wide ? 64 : 40
  const body = Buffer.concat(blobs)
  const dynstrAt = headerSize + body.length
  const dynsymAt = dynstrAt + dynstr.bytes.length
  const shstrAt = dynsymAt + dynsym.length
  const tableAt = shstrAt + shstr.bytes.length
  const header = Buffer.alloc(headerSize)
  header.writeUInt32BE(0x7f454c46, 0)
  header.writeUInt8(wide ? 2 : 1, 4)
  header.writeUInt8(1, 5)
  header.writeUInt8(1, 6)
  header.writeUInt16LE(3, 0x10)
  header.writeUInt16LE(wide ? 183 : 40, 0x12)
  header.writeUInt32LE(1, 0x14)
  const shown = headers ? sectionNames.length : 0
  if (wide) {
    header.writeBigUInt64LE(BigInt(headers ? tableAt : 0), 0x28)
    header.writeUInt16LE(sectionSize, 0x3a)
    header.writeUInt16LE(shown, 0x3c)
    header.writeUInt16LE(3, 0x3e)
  } else {
    header.writeUInt32LE(headers ? tableAt : 0, 0x20)
    header.writeUInt16LE(sectionSize, 0x2e)
    header.writeUInt16LE(shown, 0x30)
    header.writeUInt16LE(3, 0x32)
  }
  const sections = Buffer.alloc(sectionNames.length * sectionSize)
  const put = (index, name, type, offset, size, link, each = 0) => {
    const at = index * sectionSize
    sections.writeUInt32LE(shstr.offsets.get(name), at)
    sections.writeUInt32LE(type, at + 4)
    if (wide) {
      sections.writeBigUInt64LE(BigInt(offset), at + 0x18)
      sections.writeBigUInt64LE(BigInt(size), at + 0x20)
      sections.writeUInt32LE(link, at + 0x28)
      sections.writeBigUInt64LE(BigInt(each), at + 0x38)
    } else {
      sections.writeUInt32LE(offset, at + 0x10)
      sections.writeUInt32LE(size, at + 0x14)
      sections.writeUInt32LE(link, at + 0x18)
      sections.writeUInt32LE(each, at + 0x24)
    }
  }
  put(1, '.dynstr', 3, dynstrAt, dynstr.bytes.length, 0)
  put(2, '.dynsym', dynamic ? 11 : 2, dynsymAt, dynsym.length, stringsLink, entsize ?? symbolSize)
  put(3, '.shstrtab', 3, shstrAt, shstr.bytes.length, 0)
  return Buffer.concat([header, body, dynstr.bytes, dynsym, shstr.bytes, sections])
}

/**
 * A zip of `members` ({name, bytes}), stored, with an optional archive comment.
 *
 * A member with `deflate: true` is compressed, and `cutBy` drops that many bytes off the end of its
 * compressed data, which the directory then gives as its size (a stream that ends too soon).
 * `claimCompressed` and `claimUncompressed` are the sizes the central directory gives for it when
 * they are not the true ones, which is how a member that the archive cannot give in full is made,
 * and `claimCrc` is the CRC-32 it gives when that is not the one of the member's bytes.
 */
export function zip(members, comment = Buffer.alloc(0)) {
  const pieces = []
  const directory = []
  let at = 0
  for (const member of members) {
    const name = Buffer.from(member.name, 'utf8')
    const whole = member.deflate ? deflateRawSync(member.bytes) : member.bytes
    const data = member.cutBy ? whole.subarray(0, whole.length - member.cutBy) : whole
    const method = member.deflate ? 8 : 0
    const crc = member.claimCrc ?? crc32(member.bytes)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(method, 8)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(data.length, 18)
    local.writeUInt32LE(member.bytes.length, 22)
    local.writeUInt16LE(name.length, 26)
    pieces.push(local, name, data)
    const entry = Buffer.alloc(46)
    entry.writeUInt32LE(0x02014b50, 0)
    entry.writeUInt16LE(20, 6)
    entry.writeUInt16LE(method, 10)
    entry.writeUInt32LE(crc, 16)
    entry.writeUInt32LE(member.claimCompressed ?? data.length, 20)
    entry.writeUInt32LE(member.claimUncompressed ?? member.bytes.length, 24)
    entry.writeUInt16LE(name.length, 28)
    entry.writeUInt32LE(at, 42)
    directory.push(entry, name)
    at += 30 + name.length + data.length
  }
  const body = Buffer.concat(pieces)
  const central = Buffer.concat(directory)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(members.length, 8)
  end.writeUInt16LE(members.length, 10)
  end.writeUInt32LE(central.length, 12)
  end.writeUInt32LE(body.length, 16)
  end.writeUInt16LE(comment.length, 20)
  return Buffer.concat([body, central, end, comment])
}

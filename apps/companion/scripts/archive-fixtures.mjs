// The smallest archives that exercise the readers in this directory, built in memory for the
// self-tests: a dex that carries its string, type and class tables and nothing else, and a stored
// zip. They are not archives any runtime would accept.
import { Buffer } from 'node:buffer'

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
 */
export function dex({ defined = [], referenced = [], constants = [] } = {}) {
  const descriptorOf = (name) => `L${name.replaceAll('.', '/')};`
  // Every class the file names. The superclass every real class has comes first, and the merely
  // mentioned ones next, so a class_defs index is never the type index it holds.
  const types = ['java.lang.Object', ...referenced, ...defined].map(descriptorOf)
  // A real string table holds method and field names as well as class names. Enough of them come
  // first here that a descriptor's string index is never its type index, and the descriptors
  // behind them run in the opposite order to the type table.
  const strings = [
    ...types.map((_, index) => `member${index}`),
    ...constants,
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

  const header = Buffer.alloc(112)
  header.write('dex\n035\0', 0, 'latin1')
  const stringIdsAt = 112
  const typeIdsAt = stringIdsAt + strings.length * 4
  const classDefsAt = typeIdsAt + types.length * 4
  const dataAt = classDefsAt + definedTypeIndex.length * 32
  header.writeUInt32LE(strings.length, 0x38)
  header.writeUInt32LE(stringIdsAt, 0x3c)
  header.writeUInt32LE(types.length, 0x40)
  header.writeUInt32LE(typeIdsAt, 0x44)
  header.writeUInt32LE(definedTypeIndex.length, 0x60)
  header.writeUInt32LE(classDefsAt, 0x64)

  const stringIds = Buffer.alloc(strings.length * 4)
  const typeIds = Buffer.alloc(types.length * 4)
  const classDefs = Buffer.alloc(definedTypeIndex.length * 32)
  const data = []
  let at = dataAt
  strings.forEach((text, index) => {
    stringIds.writeUInt32LE(at, index * 4)
    const item = Buffer.concat([uleb(text.length), Buffer.from(text, 'utf8'), Buffer.from([0])])
    data.push(item)
    at += item.length
  })
  typeStringIndex.forEach((stringIndex, index) => typeIds.writeUInt32LE(stringIndex, index * 4))
  definedTypeIndex.forEach((typeIndex, index) => classDefs.writeUInt32LE(typeIndex, index * 32))
  return Buffer.concat([header, stringIds, typeIds, classDefs, ...data])
}

/** A zip of `members` ({name, bytes}), stored, with an optional archive comment. */
export function zip(members, comment = Buffer.alloc(0)) {
  const pieces = []
  const directory = []
  let at = 0
  for (const member of members) {
    const name = Buffer.from(member.name, 'utf8')
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt32LE(member.bytes.length, 18)
    local.writeUInt32LE(member.bytes.length, 22)
    local.writeUInt16LE(name.length, 26)
    pieces.push(local, name, member.bytes)
    const entry = Buffer.alloc(46)
    entry.writeUInt32LE(0x02014b50, 0)
    entry.writeUInt16LE(20, 6)
    entry.writeUInt32LE(member.bytes.length, 20)
    entry.writeUInt32LE(member.bytes.length, 24)
    entry.writeUInt16LE(name.length, 28)
    entry.writeUInt32LE(at, 42)
    directory.push(entry, name)
    at += 30 + name.length + member.bytes.length
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

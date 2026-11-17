// The characters that never reach the page as themselves: a copy of the
// range table in crates/wire/src/text.rs (`is_unsafe_char`: Cc, Cf, Co,
// Cs, Zl, Zp and Default_Ignorable_Code_Point, except TAB). The link test
// `js_unsafe_table_equals_wire` checks every char, so the two cannot drift.
// Sorted, inclusive [lo, hi]. No DOM.
export const UNSAFE = Object.freeze([
  [0x0, 0x8],
  [0xA, 0x1F],
  [0x7F, 0x9F],
  [0xAD, 0xAD],
  [0x34F, 0x34F],
  [0x600, 0x605],
  [0x61C, 0x61C],
  [0x6DD, 0x6DD],
  [0x70F, 0x70F],
  [0x890, 0x891],
  [0x8E2, 0x8E2],
  [0x115F, 0x1160],
  [0x17B4, 0x17B5],
  [0x180B, 0x180F],
  [0x200B, 0x200F],
  [0x2028, 0x202E],
  [0x2060, 0x206F],
  [0x3164, 0x3164],
  [0xD800, 0xF8FF],
  [0xFE00, 0xFE0F],
  [0xFEFF, 0xFEFF],
  [0xFFA0, 0xFFA0],
  [0xFFF0, 0xFFFB],
  [0x110BD, 0x110BD],
  [0x110CD, 0x110CD],
  [0x13430, 0x1343F],
  [0x1BCA0, 0x1BCA3],
  [0x1D173, 0x1D17A],
  [0xE0000, 0xE0FFF],
  [0xF0000, 0xFFFFD],
  [0x100000, 0x10FFFD],
]);

// True when code point `c` is in the table (binary search).
export function isUnsafe(c) {
  let lo = 0;
  let hi = UNSAFE.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [a, b] = UNSAFE[mid];
    if (c < a) hi = mid - 1;
    else if (c > b) lo = mid + 1;
    else return true;
  }
  return false;
}

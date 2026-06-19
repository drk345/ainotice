/**
 * AG-PROMPT-MEDICAL-PII-DETECTION-REGRESSION-034: ASCII85 (Base85) Decoder
 *
 * Decodes ASCII85-encoded data as used in PDF streams with /ASCII85Decode filter.
 * Pure function, zero dependencies, works in both browser and Node.js.
 *
 * PDF ASCII85 encoding:
 * - Groups of 5 ASCII chars (33-117, i.e. '!' to 'u') decode to 4 binary bytes
 * - 'z' is shorthand for 4 zero bytes (00 00 00 00)
 * - End-of-data marker is '~>'
 * - Whitespace is ignored
 * - Final group may be 2-4 chars, padded with 'u' (84) to decode, yielding 1-3 bytes
 */

/**
 * Decode ASCII85-encoded data to raw bytes.
 *
 * @param input - ASCII85-encoded bytes (from PDF stream between 'stream' and 'endstream')
 * @returns Decoded binary data
 */
export function decodeAscii85(input: Uint8Array): Uint8Array {
  const output: number[] = [];
  const group: number[] = [];

  for (let i = 0; i < input.length; i++) {
    const byte = input[i];

    // End-of-data marker: ~ followed by >
    if (byte === 0x7E) { // '~'
      if (i + 1 < input.length && input[i + 1] === 0x3E) { // '>'
        break;
      }
      continue; // stray '~' — skip
    }

    // Skip whitespace (space, tab, newline, carriage return)
    if (byte === 0x20 || byte === 0x09 || byte === 0x0A || byte === 0x0D) {
      continue;
    }

    // 'z' shorthand: 4 zero bytes
    if (byte === 0x7A) { // 'z'
      if (group.length !== 0) {
        // 'z' should only appear between complete groups
        // Tolerate it by flushing partial group first
        flushPartialGroup(group, output);
        group.length = 0;
      }
      output.push(0, 0, 0, 0);
      continue;
    }

    // Valid ASCII85 character range: '!' (33) to 'u' (117)
    if (byte < 0x21 || byte > 0x75) {
      continue; // Skip invalid characters
    }

    group.push(byte - 33);

    if (group.length === 5) {
      // Full group: 5 encoded chars → 4 bytes
      const value =
        group[0] * 52200625 + // 85^4
        group[1] * 614125 +   // 85^3
        group[2] * 7225 +     // 85^2
        group[3] * 85 +       // 85^1
        group[4];              // 85^0

      output.push(
        (value >>> 24) & 0xFF,
        (value >>> 16) & 0xFF,
        (value >>> 8) & 0xFF,
        value & 0xFF,
      );
      group.length = 0;
    }
  }

  // Handle final partial group
  if (group.length > 1) {
    flushPartialGroup(group, output);
  }

  return new Uint8Array(output);
}

/**
 * Flush a partial ASCII85 group (2-4 chars) at end of data.
 * Pads with 'u' (value 84) to make 5, decodes, takes first (N-1) bytes.
 */
function flushPartialGroup(group: number[], output: number[]): void {
  const n = group.length;
  if (n < 2) return;

  // Pad with 84 ('u') to fill 5 positions
  const padded = [...group];
  while (padded.length < 5) {
    padded.push(84);
  }

  const value =
    padded[0] * 52200625 +
    padded[1] * 614125 +
    padded[2] * 7225 +
    padded[3] * 85 +
    padded[4];

  // Output (n-1) bytes
  if (n >= 2) output.push((value >>> 24) & 0xFF);
  if (n >= 3) output.push((value >>> 16) & 0xFF);
  if (n >= 4) output.push((value >>> 8) & 0xFF);
}

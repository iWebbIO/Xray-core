//! Standard BLAKE3 derive-key mode with byte-string contexts.
//!
//! Go's `blake3.DeriveKey(..., string(context), ...)` permits arbitrary binary
//! contexts. The Rust blake3 API accepts only UTF-8, so encoding the context as
//! text would break this protocol. This bounded-stack, one-shot implementation
//! follows the BLAKE3 reference algorithm; it adds no new cryptographic scheme.

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const PERMUTE: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const DERIVE_KEY_CONTEXT: u32 = 32;
const DERIVE_KEY_MATERIAL: u32 = 64;

fn mix(state: &mut [u32; 16], indices: [usize; 4], x: u32, y: u32) {
    let [a, b, c, d] = indices;
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[derive(Clone, Copy)]
struct Output {
    key: [u32; 8],
    block: [u32; 16],
    counter: u64,
    length: u32,
    flags: u32,
}

impl Output {
    fn compress(&self, root: bool) -> [u32; 8] {
        let counter = if root { 0 } else { self.counter };
        let mut state = [0; 16];
        state[..8].copy_from_slice(&self.key);
        state[8..12].copy_from_slice(&IV[..4]);
        state[12] = counter as u32;
        state[13] = (counter >> 32) as u32;
        state[14] = self.length;
        state[15] = self.flags | if root { ROOT } else { 0 };
        let mut message = self.block;
        for round in 0..7 {
            mix(&mut state, [0, 4, 8, 12], message[0], message[1]);
            mix(&mut state, [1, 5, 9, 13], message[2], message[3]);
            mix(&mut state, [2, 6, 10, 14], message[4], message[5]);
            mix(&mut state, [3, 7, 11, 15], message[6], message[7]);
            mix(&mut state, [0, 5, 10, 15], message[8], message[9]);
            mix(&mut state, [1, 6, 11, 12], message[10], message[11]);
            mix(&mut state, [2, 7, 8, 13], message[12], message[13]);
            mix(&mut state, [3, 4, 9, 14], message[14], message[15]);
            if round != 6 {
                message = std::array::from_fn(|index| message[PERMUTE[index]]);
            }
        }
        std::array::from_fn(|index| state[index] ^ state[index + 8])
    }
}

fn chunk_output(input: &[u8], counter: u64, key: [u32; 8], flags: u32) -> Output {
    let mut cv = key;
    let blocks = input.len().div_ceil(64).max(1);
    for index in 0..blocks {
        let start = index * 64;
        let end = (start + 64).min(input.len());
        let mut bytes = [0; 64];
        bytes[..end - start].copy_from_slice(&input[start..end]);
        let output = Output {
            key: cv,
            block: std::array::from_fn(|i| {
                u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("four bytes"))
            }),
            counter,
            length: (end - start) as u32,
            flags: flags
                | if index == 0 { CHUNK_START } else { 0 }
                | if index + 1 == blocks { CHUNK_END } else { 0 },
        };
        if index + 1 == blocks {
            return output;
        }
        cv = output.compress(false);
    }
    unreachable!("one block exists even for empty input")
}

fn parent(left: [u32; 8], right: [u32; 8], key: [u32; 8], flags: u32) -> Output {
    let mut block = [0; 16];
    block[..8].copy_from_slice(&left);
    block[8..].copy_from_slice(&right);
    Output {
        key,
        block,
        counter: 0,
        length: 64,
        flags: flags | PARENT,
    }
}

fn hash(input: &[u8], key: [u32; 8], flags: u32) -> [u8; 32] {
    let chunks = input.len().div_ceil(1024).max(1);
    let mut stack = Vec::with_capacity(usize::BITS as usize);
    for index in 0..chunks - 1 {
        let mut cv = chunk_output(
            &input[index * 1024..(index + 1) * 1024],
            index as u64,
            key,
            flags,
        )
        .compress(false);
        let mut total = index + 1;
        while total & 1 == 0 {
            cv = parent(stack.pop().expect("completed left subtree"), cv, key, flags)
                .compress(false);
            total >>= 1;
        }
        stack.push(cv);
    }
    let mut output = chunk_output(
        &input[(chunks - 1) * 1024..],
        (chunks - 1) as u64,
        key,
        flags,
    );
    while let Some(left) = stack.pop() {
        output = parent(left, output.compress(false), key, flags);
    }
    let words = output.compress(true);
    let mut result = [0; 32];
    for (bytes, word) in result.chunks_exact_mut(4).zip(words) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    result
}

/// Exact BLAKE3 derive-key operation accepting Go-compatible arbitrary contexts.
pub fn derive_key(context: &[u8], material: &[u8]) -> [u8; 32] {
    let context_key = hash(context, IV, DERIVE_KEY_CONTEXT);
    let words = std::array::from_fn(|i| {
        u32::from_le_bytes(
            context_key[i * 4..i * 4 + 4]
                .try_into()
                .expect("four bytes"),
        )
    });
    hash(material, words, DERIVE_KEY_MATERIAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rust_blake3_across_block_chunk_and_tree_boundaries() {
        for length in [
            0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 3072, 4096, 8192, 16645,
        ] {
            let context = "c".repeat(length);
            let material: Vec<u8> = (0..length + 3).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                derive_key(context.as_bytes(), &material),
                blake3::derive_key(&context, &material)
            );
            assert_eq!(hash(&material, IV, 0), *blake3::hash(&material).as_bytes());
        }
    }

    #[test]
    fn independent_binary_context_vectors() {
        // Generated by a separate recursive Python BLAKE3 reference, checked
        // against the optimized Python extension for hash/UTF-8 derive modes.
        let material: Vec<u8> = (0..96).collect();
        for (length, expected) in [
            (
                16,
                "25ff1684882bc74c6771e6ef13d4ab6396939d563d470950c3c5a8d368739878",
            ),
            (
                1216,
                "074da776fd6441511cc850699000c5fb6c855acdef23ac3bf73b0ccdca47b8fd",
            ),
            (
                16645,
                "5915ed916b68025eec1384b244326c4f77f3adfaa9918af289a1f1def83bc34b",
            ),
        ] {
            let context: Vec<u8> = (0..length).map(|i| (i * 17 + 255) as u8).collect();
            let actual: String = derive_key(&context, &material)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(actual, expected);
        }
    }
}

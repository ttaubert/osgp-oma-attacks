/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate rand;
extern crate osgp_oma_digest;

use rand::{Rng, OsRng};
use osgp_oma_digest::OMADigest;

pub struct BlackBox {
  key: [u8; 12]
}

impl BlackBox {
  pub fn new() -> Self {
    let mut rng = OsRng::new().unwrap();

    // Generate a random key.
    let mut key = [0u8; 12];
    rng.fill_bytes(&mut key);

    BlackBox { key: key }
  }

  pub fn digest(&self, msg: &[u8]) -> [u8; 8] {
    msg.oma_digest(&self.key)
  }
}

pub fn recover_6th_omak_byte<F>(digest: F) -> u8
    where F: Fn(&[u8]) -> [u8; 8]
{
  let mut msg = [0u8; 144];

  // Get the hash of the empty message under the unknown key.
  let hash = digest(&msg);

  // For every bit of the 6th byte...
  (0..8).fold(0, |byte, j| {
    // Inject differential.
    msg[135 - j] ^= 0x80;

    // Get the new internal state.
    let diff = digest(&msg);

    // Recover the key bit.
    let lsb = (hash[j] ^ diff[j]) & 1;

    // Merge into accumulator.
    byte | (lsb << (7 - j))
  })
}

#[cfg(test)]
mod test {
  use BlackBox;
  use recover_6th_omak_byte;

  #[test]
  fn test_recover_6th_omak_byte() {
    let blackbox = BlackBox::new();

    // Bitwise recovery of the OMAK's 6th byte.
    let byte = recover_6th_omak_byte(|data| blackbox.digest(data));

    // Check we correctly recovered the byte.
    assert_eq!(byte, blackbox.key[5]);
  }
}


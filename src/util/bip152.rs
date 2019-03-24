// Rust Bitcoin Library
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! BIP152 Compact Blocks
//!
//! Implementation of compact blocks data structure and algorithms.
//!

use std::{error, fmt, io};

use hashes::{hex, sha256, sha256d, siphash24, Hash};

use blockdata::block::{Block, BlockHeader};
use blockdata::transaction::Transaction;
use consensus::encode::{self, Decodable, Encodable, VarInt};
use util::endian;
use util::hash::BitcoinHash;

/// A BIP-152 error
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// An unknown version number was used.
    UnknownVersion,
    /// A transaction index is requested that is out
    /// of range from the corresponding block.
    TxIndexOutOfRange(u64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = error::Error::description(self);
        match *self {
            Error::TxIndexOutOfRange(i) => write!(f, "{}: {}", desc, i),
            _ => f.write_str(desc),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        None
    }

    fn description(&self) -> &str {
        match *self {
            Error::UnknownVersion => "an unknown version number was used",
            Error::TxIndexOutOfRange(_) => {
                "a transaction index is requested that is out of range from the corresponding block"
            }
        }
    }
}

/// A PrefilledTransaction structure is used in HeaderAndShortIDs to
/// provide a list of a few transactions explicitly.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PrefilledTransaction(pub u64, pub Transaction);

impl Encodable for PrefilledTransaction {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        Ok(VarInt(self.0).consensus_encode(&mut s)? + self.1.consensus_encode(s)?)
    }
}

impl Decodable for PrefilledTransaction {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<PrefilledTransaction, encode::Error> {
        let idx = VarInt::consensus_decode(&mut d)?.0;
        let tx = Transaction::consensus_decode(d)?;
        Ok(PrefilledTransaction(idx, tx))
    }
}

/// Short transaction IDs are used to represent a transaction without sending a full 256-bit hash.
#[derive(PartialEq, Eq, Clone, Default)]
pub struct ShortId(pub [u8; 6]);

impl ShortId {
    /// Calculate the SipHash24 keys used to calculate short IDs.
    pub fn calculate_siphash_keys(header: &BlockHeader, nonce: u64) -> (u64, u64) {
        // 1. single-SHA256 hashing the block header with the nonce appended (in little-endian)
        let h = {
            let mut b: Vec<u8> = vec![];
            header.consensus_encode(&mut b).expect("Vec<u8>");
            nonce.consensus_encode(&mut b).expect("Vec<u8>");
            sha256::Hash::hash(&b)
        };

        // 2. Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1)
        // set to the first two little-endian 64-bit integers from the above hash, respectively.
        (endian::slice_to_u64_le(&h[0..8]), endian::slice_to_u64_le(&h[8..16]))
    }

    /// Calculate the short ID with the given (w)txid and using the provided SipHash keys.
    pub fn with_siphash_keys(txid: &sha256d::Hash, siphash_keys: (u64, u64)) -> ShortId {
        // 2. Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1)
        // set to the first two little-endian 64-bit integers from the above hash, respectively.
        let siphash = siphash24::Hash::hash_with_keys(siphash_keys.0, siphash_keys.1, &txid[..]);

        // 3. Dropping the 2 most significant bytes from the SipHash output to make it 6 bytes.
        let mut id = ShortId([0; 6]);
        id.0.copy_from_slice(&siphash[0..6]);
        id
    }
}

impl hex::FromHex for ShortId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where
        I: Iterator<Item = Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator,
    {
        Ok(ShortId(hex::FromHex::from_byte_iter(iter)?))
    }
}

impl fmt::LowerHex for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::format_hex(&self.0[..], f)
    }
}

impl fmt::Display for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::Debug for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Encodable for ShortId {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, encode::Error> {
        self.0.consensus_encode(s)
    }
}

impl Decodable for ShortId {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<ShortId, encode::Error> {
        Ok(ShortId(Decodable::consensus_decode(d)?))
    }
}

/// A HeaderAndShortIDs structure is used to relay a block header, the short transactions
/// IDs used for matching already-available transactions, and a select few transactions
/// which we expect a peer may be missing.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct HeaderAndShortIds {
    /// The header of the block being provided.
    pub header: BlockHeader,
    ///  A nonce for use in short transaction ID calculations.
    pub nonce: u64,
    ///  The short transaction IDs calculated from the transactions
    ///  which were not provided explicitly in prefilled_txs.
    pub short_ids: Vec<ShortId>,
    ///  Used to provide the coinbase transaction and a select few
    ///  which we expect a peer may be missing.
    pub prefilled_txs: Vec<PrefilledTransaction>,
}
impl_consensus_encoding!(HeaderAndShortIds, header, nonce, short_ids, prefilled_txs);

impl HeaderAndShortIds {
    /// Create a new HeaderAndShortIds from a full block.
    ///
    /// The version number must be either 1 or 2.
    ///
    /// The [prefill] slice indicates which transactions should be prefilled in
    /// the block. It should contain the indexes in the block of the txs to
    /// prefill. It must be in ordered. 0 should not be included as the
    /// coinbase tx is always prefilled.
    ///
    /// > Nodes SHOULD NOT use the same nonce across multiple different blocks.
    ///
    /// Possible [Error] variants:
    /// - UnknownVersion: If the version is not 1 or 2.
    /// number of transactions in the block.
    pub fn from_block(
        block: &Block,
        nonce: u64,
        version: u32,
        mut prefill: &[usize],
    ) -> Result<HeaderAndShortIds, Error> {
        if version != 1 && version != 2 {
            return Err(Error::UnknownVersion);
        }

        let siphash_keys = ShortId::calculate_siphash_keys(&block.header, nonce);

        let mut prefilled = vec![];
        let mut short_ids = vec![];
        let mut last_prefill = 0;
        for (idx, tx) in block.txdata.iter().enumerate() {
            // Check if we should prefill this tx.
            let prefill_tx = if prefill.get(0) == Some(&idx) {
                prefill = &prefill[1..];
                true
            } else {
                idx == 0 // Always prefill coinbase.
            };

            if prefill_tx {
                let diff_idx = idx - last_prefill;
                last_prefill = idx;
                prefilled.push(PrefilledTransaction(
                    diff_idx as u64,
                    match version {
                        1 => {
                            // strip witness for version 1
                            let mut no_witness = tx.clone();
                            no_witness.input.iter_mut().for_each(|i| i.witness.clear());
                            no_witness
                        }
                        2 => tx.clone(),
                        _ => unreachable!(),
                    },
                ));
            } else {
                short_ids.push(ShortId::with_siphash_keys(
                    &match version {
                        1 => tx.txid(),
                        2 => tx.bitcoin_hash(), //TODO(stevenroose) use wtxid explicitly
                        _ => unreachable!(),
                    },
                    siphash_keys,
                ));
            }
        }

        Ok(HeaderAndShortIds {
            header: block.header.clone(),
            nonce: nonce,
            // Provide coinbase prefilled.
            prefilled_txs: prefilled,
            short_ids: short_ids,
        })
    }
}

/// A BlockTransactionsRequest structure is used to list transaction indexes
/// in a block being requested.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BlockTransactionsRequest {
    ///  The blockhash of the block which the transactions being requested are in.
    pub block_hash: sha256d::Hash,
    ///  The indexes of the transactions being requested in the block.
    pub indexes: Vec<u64>,
}

impl Encodable for BlockTransactionsRequest {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        let mut len = self.block_hash.consensus_encode(&mut s)?;
        // Manually encode indexes because they are differentially encoded VarInts.
        len += VarInt(self.indexes.len() as u64).consensus_encode(&mut s)?;
        let mut last_idx = 0;
        for idx in &self.indexes {
            len += VarInt(*idx - last_idx).consensus_encode(&mut s)?;
            last_idx = *idx;
        }
        Ok(len)
    }
}

impl Decodable for BlockTransactionsRequest {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<BlockTransactionsRequest, encode::Error> {
        Ok(BlockTransactionsRequest {
            block_hash: sha256d::Hash::consensus_decode(&mut d)?,
            indexes: {
                // Manually decode indexes because they are differentially encoded VarInts.
                let nb_indexes = VarInt::consensus_decode(&mut d)?.0 as usize;
                let mut indexes = Vec::with_capacity(nb_indexes);
                let mut last_index = 0;
                for _ in 0..nb_indexes {
                    let differential: VarInt = Decodable::consensus_decode(&mut d)?;
                    last_index += differential.0;
                    indexes.push(last_index);
                }
                indexes
            },
        })
    }
}

/// A BlockTransactions structure is used to provide some of
/// the transactions in a block, as requested.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BlockTransactions {
    ///  The blockhash of the block which the transactions being provided are in.
    pub block_hash: sha256d::Hash,
    ///  The transactions provided.
    pub transactions: Vec<Transaction>,
}
impl_consensus_encoding!(BlockTransactions, block_hash, transactions);

impl BlockTransactions {
    /// Construct a BlockTransactions from a BlockTransactionsRequest and the corresponsing full
    /// Block by providing all requested transactions.
    ///
    /// Possible [Error] variants:
    /// - TxIndexOutOfRange: When a transaction index is requested that is our
    /// of range from the corresponding block.
    pub fn from_request(
        request: &BlockTransactionsRequest,
        block: &Block,
    ) -> Result<BlockTransactions, Error> {
        Ok(BlockTransactions {
            block_hash: request.block_hash,
            transactions: {
                let mut txs = Vec::with_capacity(request.indexes.len());
                for idx in &request.indexes {
                    if *idx >= block.txdata.len() as u64 {
                        return Err(Error::TxIndexOutOfRange(*idx));
                    }
                    txs.push(block.txdata[*idx as usize].clone());
                }
                txs
            },
        })
    }
}

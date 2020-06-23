//!
//! BIP37 Connection Bloom filtering network messages
//!

/// `filterload` message sets the current bloom filter
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterLoad {
    /// The filter itself
    filter: Vec<u8>,
    /// The number of hash functions to use
    hash_funcs: u32,
    /// A random value
    tweak: u32,
    /// Controls how matched items are added to the filter
    flags: u8,
}

impl_consensus_encoding!(FilterLoad, filter, hash_funcs, tweak, flags);

/// `filteradd` message updates the current filter with new data
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilterAdd {
    /// The data element to add to the current filter.
    data: Vec<u8>,
}

impl_consensus_encoding!(FilterAdd, data);

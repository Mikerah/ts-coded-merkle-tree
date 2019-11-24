
// Hash is 32 bytes long
let HASH_SIZE: number = 32;

// Size of each symbol in a block
let SYMBOL_SIZE: number = 256;

// Number of hashes to aggregate to form a new symbol
let C: number = 8;

// Coding rage
let RATE: number = 0.25;

// At each layer, the number of symbols reduces by REDUCTION_FACTOR
let REDUCTION_FACTOR = C * RATE;

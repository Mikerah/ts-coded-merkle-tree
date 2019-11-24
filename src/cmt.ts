import * as utils from "./utils";
import {assert} from "assert";

/**
 * Implementation of Coded Merkle Trees
 * introduced in Yu, et al, 2019
 *
 */

export class CodeMerkleTree {    
    private _roots: Buffer[];
    private _tree: Buffer[][];
    private _hidePattern: number[][];

    /** Constants **/
    // Hash is 32 bytes long
    private readonly HASH_SIZE: number = 32;

    // Size of each symbol in a block
    private readonly SYMBOL_SIZE: number = 256;

    // Number of hashes to aggregate to form a new symbol
    private readonly C: number = 8;

    // Coding rage
    private readonly RATE: number = 0.25;

    // At each layer, the number of symbols reduces by REDUCTION_FACTOR
    private readonly REDUCTION_FACTOR: number = this.C * this.RATE;

    constructor(data: Buffer, headerSize: number) {
        // Pad the data
        let paddedData = utils.pad(data);

        // Generate symbols in preparation for constructing the tree
        // Each subarray represents a symbol in bytes
        let symbols = [];
        for (let i=0; i < paddedData.length; this.SYMBOL_SIZE){
            symbols.push(paddedData.slice(i, (i + this.SYMBOL_SIZE) % paddedData.length));
        }

        // Coded symbols using LDPC codes
        let codedSymbols = utils.LDPCEncode(symbols, this.RATE);

        // Number of levels in the CMT given the header size
        let nLevels = Math.floor(Math.log(codedSymbols.length / headerSize) / (Math.log(this.REDUCTION_FACTOR) + 1));

        this._tree = [codedSymbols];
        for (let i=0; i < nLevels; i++) {
            let s = utils.hashAndAggregate(this.tree[i]);
            this._tree.push(utils.LDPCEncode(s, this.RATE));
        }

        this._roots = [];
        let treeRoots = this._tree[nLevels - 1];
        treeRoots.forEach((root) => {
            this._roots.push(utils.sha3(root));
        });

        this._hidePattern = [];
    }

    /**
     * Returns the hashed roots of the CMT
     * 
     */
    get roots(): Buffer[] {
        return this.roots;
    }

    /**
     * Returns the entire CMT
     * 
     * 
     */
    get tree(): Buffer[][] {
        return this.tree;
    }

    /**
     * Sets a hide pattern that encodes the availability of each coded symbol.
     * If 1 is at a position in the array, then that symbol is unavailable.
     * If 0 is at a position in the array, then that symbol is available
     * @param hidePattern 
     * 
     */
    set hidePattern(hidePattern: number[][]) {
        this._hidePattern = hidePattern;
    }

    /**
     * Returns requested symbols along with their merkle proofs
     * @param level 
     * @param requestedSymbols 
     */
    sample(level: number, requestedSymbols: number[]): [Buffer, Buffer[]][] {
        let symbols: [Buffer, Buffer[]][] = [];
        requestedSymbols.forEach((index) => {
            if (this._hidePattern[level][index] == 0) {
                let proof = this.generateProof(level, index);
                symbols.push([this._tree[level][index], proof]);
            } else {
                console.log("Requested symbol at level {} with index {} is not available", level, index);
                return [];
            }

        });
        return symbols;
    }

    /**
     * 
     * @param level 
     * @param index 
     */
    generateProof(level: number, index: number): Buffer[] {
        assert(0 <= index);
        assert(index < this._tree[level].length);

        // Arrays that will contain the final merkle proof
        let merkleProof: Buffer[] = [];
        // Index of a symbol in the proof list for its level
        let movingIndex: number = index;
        // # of systematic symbols in a level
        let movingK: number = Math.floor(this._tree[level].length * this.RATE);

        for (let i=level; i < this._tree.length - 1; i++) {
            movingIndex = utils.nextIndex(movingIndex, movingK);
            merkleProof.push(this._tree[i + 1][movingIndex]);
            movingK = Math.floor(movingK / this.REDUCTION_FACTOR);
        }
        return merkleProof;        
    }

    /**
     * 
     * @param level 
     * @param index 
     * @param symbol 
     * @param proof 
     * @param K 
     * @param roots 
     */
    verifyProof(level: number, index: number, symbol: Buffer, proof: Buffer[], K: number, roots: Buffer[]): boolean {
        let currentIndex = index;
        let currentSymbol = symbol;
        let currentLevel = level;
        let currentK = Math.floor(K / (Math.pow(this.REDUCTION_FACTOR, level)));

        for (let s of proof) {
            let hashes = utils.partitionByteStream(s);
            let hashIndex: number;
            if (currentIndex <= currentK - 1) {
                hashIndex = currentIndex % this.REDUCTION_FACTOR;
            } else {
                hashIndex = ((currentIndex - currentK) % ((this.C - this.REDUCTION_FACTOR)) + this.REDUCTION_FACTOR);
            }

            if (utils.sha3(currentSymbol) != hashes[hashIndex]) {
                console.log('Failed at level {} with symbol index {}', currentLevel, currentIndex);
                return false;
            } else {
                currentIndex = utils.nextIndex(currentIndex, currentK);
                currentSymbol = s;
                currentK = Math.floor(currentK / this.REDUCTION_FACTOR);
                currentLevel = currentLevel + 1;
            }
        }

        if (utils.sha3(currentSymbol) === this._roots[currentIndex]){
            return true;
        } else {
            return false;
        }
    }
}

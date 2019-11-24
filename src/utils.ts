// Utilities for Coded Merkle Trees
import {SHA3} from "sha3";

export function pad(data: Buffer): Buffer {

} 

export function LDPCEncode(symbols: Buffer[], rate: number): Buffer[] {

}

export function hashAndAggregate(codedSymbols: Buffer[]): Buffer[] {

}

export function sha3(x: any): Buffer {
    const sha = new SHA3(256);
    sha.update(x);
    return Buffer.from(sha.digest('hex'));
}

export function partitionByteStream(data: Buffer): Buffer[] {

}

export function nextIndex(index: number, k: number): number {

}
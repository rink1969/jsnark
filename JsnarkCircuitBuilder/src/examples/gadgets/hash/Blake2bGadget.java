/*******************************************************************************
 * Author: zhiwei ning <rink1969@cryptape.com>
 *******************************************************************************/
package examples.gadgets.hash;

import java.util.Arrays;
import java.math.BigInteger;

import util.Util;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;

public class Blake2bGadget extends Gadget {

	private static final BigInteger[] H = {
		new BigInteger("6a09e667f3bcc908", 16), new BigInteger("bb67ae8584caa73b", 16), 
		new BigInteger("3c6ef372fe94f82b", 16), new BigInteger("a54ff53a5f1d36f1", 16), 
		new BigInteger("510e527fade682d1", 16), new BigInteger("9b05688c2b3e6c1f", 16),
		new BigInteger("1f83d9abfb41bd6b", 16), new BigInteger("5be0cd19137e2179", 16)};

	private static final int SIGMA[][] = {
			{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
			{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
			{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
			{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
			{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
			{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
			{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
			{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
			{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
	};

	// the key of blake2b in zcash "ZcashComputehSig"
	private static final BigInteger Key = new BigInteger("5a63617368436f6d7075746568536967", 16);
	private static final int KeyLenInBytes = 16;
	private static final BigInteger finalFlags = new BigInteger("FFFFFFFFFFFFFFFF", 16);
	// for blake2b-256
	private static final int OutputLengthInBytes = 32;

	private Wire[] unpaddedInputs;

	private int bitwidthPerInputElement;
	private int totalLengthInBytes;

	private Wire[] preparedInputBits;
	private Wire[] output;

	public Blake2bGadget(Wire[] ins, int bitWidthPerInputElement, int totalLengthInBytes, boolean binaryOutput,
						 boolean paddingRequired, String... desc) {

		super(desc);
		if (totalLengthInBytes * 8 > ins.length * bitWidthPerInputElement
				|| totalLengthInBytes * 8 < (ins.length - 1) * bitWidthPerInputElement) {
			throw new IllegalArgumentException("Inconsistent Length Information");
		}

		this.unpaddedInputs = ins;
		this.bitwidthPerInputElement = bitWidthPerInputElement;
		this.totalLengthInBytes = totalLengthInBytes;

		buildCircuit();

	}

	protected void buildCircuit() {
		Wire keyWire = generator.createConstantWire(Key);

		Wire[] outDigest = new Wire[8];
		Wire[] hWires = new Wire[H.length];
		for (int i = 0; i < H.length; i++) {
			hWires[i] = generator.createConstantWire(H[i]);
		}

		//h0 = h0 xor 0x0101kknn
		//where kk is Key Length (in bytes)
		//nn is Desired Hash Length (in bytes)
		long tmp = 0x0101 * 0x10000 + KeyLenInBytes * 0x100 + OutputLengthInBytes;
		hWires[0] = hWires[0].xorBitwise(tmp, 64, "h0 xor 0x0101kknn");

		//compress key
		Wire[] key_chunk = generator.generateZeroWireArray(128);
		Wire[] keyWireBytes = keyWire.getBitWires(KeyLenInBytes * 8).packBitsIntoWords(8);
		for (int i = 0; i < KeyLenInBytes; i++) {
			key_chunk[i] = keyWireBytes[KeyLenInBytes- 1 - i];
			generator.addDebugInstruction(key_chunk[i], "key_chunk"+i);
		}
		//compress(hWires, key_chunk, 0, false);

		//Each time we Compress we record how many bytes have been compressed
		// cBytesCompressed = 0
		// cBytesRemaining  = cbMessageLen
		int cBytesCompressed = 0;
		int cBytesRemaining = totalLengthInBytes;

		// pad with zeros to make key 128-bytes
		// then prepend it to the message M
		cBytesRemaining = cBytesRemaining + 128;
		preparedInputBits = new Wire[cBytesRemaining];
		Arrays.fill(preparedInputBits, generator.getZeroWire());
		System.arraycopy(key_chunk, 0, preparedInputBits, 0, 128);
		System.arraycopy(unpaddedInputs, 0, preparedInputBits, 128, totalLengthInBytes);

		// Compress whole 128-byte chunks of the message, except the last chunk
		int chunk_index = 0;
		while (cBytesRemaining > 128) {
			// chunk = get next 128 bytes of message M
			Wire[] chunk = generator.generateZeroWireArray(128);
			System.arraycopy(preparedInputBits, chunk_index * 128, chunk, 0, 128);

			cBytesCompressed = cBytesCompressed + 128;
			cBytesRemaining = cBytesRemaining - 128;
			chunk_index = chunk_index + 1;
			compress(hWires, chunk, cBytesCompressed, false);
		}

		// padding the last chunk
		Wire[] chunk = new Wire[128];
		for (int i = 0; i < 128; i++) {
			chunk[i] = generator.getZeroWire();
		}
		System.arraycopy(preparedInputBits, chunk_index * 128, chunk, 0, cBytesRemaining);
		cBytesCompressed = cBytesCompressed + cBytesRemaining;
		compress(hWires, chunk, cBytesCompressed, true);

		// first cbHashLen bytes of little endian state vector h
		outDigest[0] = hWires[0];
		outDigest[1] = hWires[1];
		outDigest[2] = hWires[2];
		outDigest[3] = hWires[3];
		outDigest[4] = hWires[4];
		outDigest[5] = hWires[5];
		outDigest[6] = hWires[6];
		outDigest[7] = hWires[7];

		output = new Wire[OutputLengthInBytes];
		//each h is 64 bit or 8 bytes
		for (int i = 0; i < OutputLengthInBytes / 8; i++) {
			Wire[] bits = outDigest[i].getBitWires(64).packBitsIntoWords(8);
			for (int j = 0; j < 8; j++) {
				output[j + i * 8] = bits[j];
			}
		}
	}

	private void compress(Wire[] h, Wire[] chunk, int t, boolean isLastChunk) {
		Wire[] v = new Wire[16];
		for (int i = 0; i < 8; i++) {
			v[i] = h[i];
		}
		for (int i = 8; i < 16; i++) {
			v[i] = generator.createConstantWire(H[i - 8]);
		}

		Wire[] prepare_t = generator.createConstantWire(t).getBitWires(128).packBitsIntoWords(64);
		generator.addDebugInstruction(prepare_t[0], "t0");
		generator.addDebugInstruction(prepare_t[1], "t1");

		v[12] = v[12].xorBitwise(prepare_t[0], 64, "compress xor v12");
		v[13] = v[13].xorBitwise(prepare_t[1], 64, "compress xor v13");

		if (isLastChunk) {
			v[14] = v[14].xorBitwise(finalFlags, 64);
		}

	    //WireArray chunkArray = new WireArray(chunk);
		for (int i = 0; i < 16; i++) {
			generator.addDebugInstruction(chunk[i], "chunk"+i);
		}
		Wire[] m = new Wire[16];
		Arrays.fill(m, generator.getZeroWire());
		for (int i = 0; i < 16; i++) {
			for (int j = 0; j < 8; j++) {
				m[i] = m[i].shiftLeft(64, 8).add(chunk[i * 8 + 8 - 1 - j]).trimBits(65, 64);
			}
		}
		for  (int i = 0; i < 16; i++) {
			generator.addDebugInstruction(m[i], "m"+i);
		}
		for (int i = 0; i < 16; i++) {
			generator.addDebugInstruction(v[i], "v"+i);
		}


		for (int i = 0; i < 12; i++) {
			int[] s = SIGMA[i % 10];
			mix(v, 0, 4, 8, 12, m, s[0], s[1]);
			mix(v, 1, 5, 9, 13, m, s[2], s[3]);
			mix(v, 2, 6, 10, 14, m, s[4], s[5]);
			mix(v, 3, 7, 11, 15, m, s[6], s[7]);

			mix(v, 0, 5, 10, 15, m, s[8], s[9]);
			mix(v, 1, 6, 11, 12, m, s[10], s[11]);
			mix(v, 2, 7, 8, 13, m, s[12], s[13]);
			mix(v, 3, 4, 9, 14, m, s[14], s[15]);
		}

		for (int i = 0; i < 16; i++) {
			generator.addDebugInstruction(v[i], "v"+i);
		}

		for (int i = 0; i < 8; i++) {
			h[i] = h[i].xorBitwise(v[i], 64).xorBitwise(v[i + 8], 64);
			generator.addDebugInstruction(h[i], "h"+i);
		}
	}

	private void mix(Wire[] v, int a, int b, int c, int d, Wire[] m, int x, int y) {
		v[a] = v[a].add(v[b]).add(m[x]).trimBits(66, 64);
		v[d] = v[d].xorBitwise(v[a], 64).rotateRight(64, 32);

		v[c] = v[c].add(v[d]).trimBits(65, 64);
		v[b] = v[b].xorBitwise(v[c], 64).rotateRight(64, 24);

		v[a] = v[a].add(v[b]).add(m[y]).trimBits(66, 64);
		v[d] = v[d].xorBitwise(v[a], 64).rotateRight(64, 16);

		v[c] = v[c].add(v[d]).trimBits(65, 64);
		v[b] = v[b].xorBitwise(v[c], 64).rotateRight(64, 63);
	}

	/**
	 * outputs digest as 32-bit words
	 */
	@Override
	public Wire[] getOutputWires() {
		return output;
	}
}

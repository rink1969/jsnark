/*******************************************************************************
 * Author: zhiwei ning <rink1969@cryptape.com>
 *******************************************************************************/
package examples.tests.hash;

import junit.framework.TestCase;

import org.junit.Test;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.Blake2bGadget;

/**
 * Tests Blake2b standard cases.
 * 
 */

public class Blake2b_Test extends TestCase {

	@Test
	public void testCase1() {

		String inputStr = "";
		String expectedDigest = "e58199f28d56fea2ec39fa5e6f2720d27a38d0b187c1cde079d37e3f799b5dd0";

		CircuitGenerator generator = new CircuitGenerator("Blake2b_Test1") {

			Wire[] inputWires;

			@Override
			protected void buildCircuit() {
				inputWires = createInputWireArray(inputStr.length());
				Wire[] digest = new Blake2bGadget(inputWires, 8, inputStr.length(), false, true, "").getOutputWires();
				makeOutputArray(digest);
			}

			@Override
			public void generateSampleInput(CircuitEvaluator e) {
				// no input needed
			}
		};

		generator.generateCircuit();
		generator.evalCircuit();
		CircuitEvaluator evaluator = generator.getCircuitEvaluator();

		String outDigest = "";
		for (Wire w : generator.getOutWires()) {
			outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
		}
        assertEquals(expectedDigest, outDigest);
	}

	@Test
	public void testCase2() {

		String inputStr = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		String expectedDigest = "5ef99720a55fd1a9b7161424a77e2b86bf77b08e764c8d5659440b9c8c930917";

		CircuitGenerator generator = new CircuitGenerator("Blake2b_Test2") {

			Wire[] inputWires;

			@Override
			protected void buildCircuit() {
				inputWires = createInputWireArray(inputStr.length());
				Wire[] digest = new Blake2bGadget(inputWires, 8, inputStr.length(), false, true, "").getOutputWires();
				makeOutputArray(digest);
			}

			@Override
			public void generateSampleInput(CircuitEvaluator e) {
				for (int i = 0; i < inputStr.length(); i++) {
					e.setWireValue(inputWires[i], inputStr.charAt(i));
				}
			}
		};

		generator.generateCircuit();
		generator.evalCircuit();
		CircuitEvaluator evaluator = generator.getCircuitEvaluator();

		String outDigest = "";
		for (Wire w : generator.getOutWires()) {
			outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
		}
        assertEquals(expectedDigest, outDigest);
	}

	@Test
	public void testCase3() {

		String inputStr = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
		String expectedDigest = "d0fc4d095e3ad9a8126851d46cae8ab300301d0317d3b30c7fbad84225e9cb99";

		CircuitGenerator generator = new CircuitGenerator("Blake2b_Test3") {

			Wire[] inputWires;

			@Override
			protected void buildCircuit() {
				inputWires = createInputWireArray(inputStr.length());
				Wire[] digest = new Blake2bGadget(inputWires, 8, inputStr.length(), false, true, "").getOutputWires();
				makeOutputArray(digest);
			}

			@Override
			public void generateSampleInput(CircuitEvaluator e) {
				for (int i = 0; i < inputStr.length(); i++) {
					e.setWireValue(inputWires[i], inputStr.charAt(i));
				}
			}
		};

		generator.generateCircuit();
		generator.evalCircuit();
		CircuitEvaluator evaluator = generator.getCircuitEvaluator();

		String outDigest = "";
		for (Wire w : generator.getOutWires()) {
			outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
		}
        assertEquals(expectedDigest, outDigest);
	}

	@Test
	public void testCase4() {

		String inputStr = "abc";
		String expectedDigest = "4ebf7df5e1b1d1c8837bb6bb970eb076130ec5e21287473e76c286c83179435b";

		CircuitGenerator generator = new CircuitGenerator("Blake2b_Test4") {

			Wire[] inputWires;

			@Override
			protected void buildCircuit() {
				inputWires = createInputWireArray(inputStr.length());
				Wire[] digest = new Blake2bGadget(inputWires, 8, inputStr.length(), false, true, "").getOutputWires();
				makeOutputArray(digest);
			}

			@Override
			public void generateSampleInput(CircuitEvaluator e) {
				for (int i = 0; i < inputStr.length(); i++) {
					e.setWireValue(inputWires[i], inputStr.charAt(i));
				}
			}
		};

		generator.generateCircuit();
		generator.evalCircuit();
		CircuitEvaluator evaluator = generator.getCircuitEvaluator();

		String outDigest = "";
		for (Wire w : generator.getOutWires()) {
			outDigest += Util.padZeros(evaluator.getWireValue(w).toString(16), 2);
		}
        assertEquals(expectedDigest, outDigest);
	}
}

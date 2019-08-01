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
import examples.gadgets.hash.EaglesongGadget;

/**
 * Tests Eaglesong standard cases.
 * 
 */

public class Eaglesong_Test extends TestCase {

	@Test
	public void testCase1() {

		String inputStr = "";
		String expectedDigest = "9e4452fc7aed93d7240b7b55263792befd1be09252b456401122ba71a56f62a0";

		CircuitGenerator generator = new CircuitGenerator("Eaglesong_Test") {

			Wire[] inputWires;

			@Override
			protected void buildCircuit() {
				inputWires = createInputWireArray(inputStr.length());
				Wire[] digest = new EaglesongGadget(inputWires, inputStr.length()).getOutputWires();
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

		String inputStr = "1111111111111111111111111111111111\n";
		String expectedDigest = "a50a3310f78cbaeadcffe2d46262119eeeda9d6568b4df1b636399742c867aca";

        CircuitGenerator generator = new CircuitGenerator("Eaglesong_Test") {

            Wire[] inputWires;

            @Override
            protected void buildCircuit() {
                inputWires = createInputWireArray(inputStr.length());
                Wire[] digest = new EaglesongGadget(inputWires, inputStr.length()).getOutputWires();
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

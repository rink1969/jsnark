/*******************************************************************************
 * Author: zhiwei ning <rink1969@cryptape.com>
 *******************************************************************************/
package examples.generators.hash;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.Blake2bGadget;

public class Blake2bCircuitGenerator extends CircuitGenerator {

	private Wire[] inputWires;
	private Blake2bGadget Blake2bGadget;

	public Blake2bCircuitGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {

		// assuming the circuit input will be 64 bytes
		inputWires = createInputWireArray(64);
		// this gadget is not applying any padding.
		Blake2bGadget = new Blake2bGadget(inputWires, 8, 64, false, false);
		Wire[] digest = Blake2bGadget.getOutputWires();
		makeOutputArray(digest, "digest");		
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		String inputStr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
		for (int i = 0; i < inputWires.length; i++) {
			evaluator.setWireValue(inputWires[i], inputStr.charAt(i));
		}
	}

	public static void main(String[] args) throws Exception {
		Blake2bCircuitGenerator generator = new Blake2bCircuitGenerator("balke2b");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}

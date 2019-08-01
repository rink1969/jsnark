/*******************************************************************************
 * Author: zhiwei ning <rink1969@cryptape.com>
 *******************************************************************************/
package examples.generators.hash;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.EaglesongGadget;

public class EaglesongCircuitGenerator extends CircuitGenerator {

	private Wire[] inputWires;
	private EaglesongGadget eaglesongGadget;

	public EaglesongCircuitGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		// assuming the circuit input will be 64 bytes
		inputWires = createInputWireArray(64);
		eaglesongGadget = new EaglesongGadget(inputWires, 64);
		Wire[] digest = eaglesongGadget.getOutputWires();
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
        EaglesongCircuitGenerator generator = new EaglesongCircuitGenerator("eaglesong");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}

}

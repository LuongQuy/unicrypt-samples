package ch.bfh.unicrypt.crypto.encoder;

import ch.bfh.unicrypt.Example;
import ch.bfh.unicrypt.crypto.encoder.classes.ZModToECPolynomialField;
import ch.bfh.unicrypt.crypto.encoder.classes.ZModToECZModPrime;
import ch.bfh.unicrypt.crypto.encoder.interfaces.Encoder;
import ch.bfh.unicrypt.math.algebra.additive.classes.ECPolynomialField;
import ch.bfh.unicrypt.math.algebra.additive.classes.ECZModPrime;
import ch.bfh.unicrypt.math.algebra.additive.parameters.ECPolynomialFieldParameters;
import ch.bfh.unicrypt.math.algebra.additive.parameters.ECZModPrimeParameters;
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element;

/**
 * @author C. Lutz
 * @author R. Haenni
 */
public class ECEncoderExample1 {

	// Example to show how to encode an element from ZModPrime into an elliptic curve over Fq
	public static void example1() throws Exception {

		ECZModPrime ecFp = ECZModPrime.getInstance(ECZModPrimeParameters.SECP521r1);
		Encoder encoder = ZModToECZModPrime.getInstance(ecFp, 10);

		Element message = encoder.getDomain().getElementFrom(278);
		Element encMessage = encoder.encode(message);
		Element decMessage = encoder.decode(encMessage);

		System.out.println(message);
		System.out.println(decMessage);
	}

	// Example to show how to encode an element from ZModPrime into an elliptic curve over F2m
	public static void example2() throws Exception {

		ECPolynomialField ecF2m = ECPolynomialField.getInstance(ECPolynomialFieldParameters.SECT113r1);
		Encoder encoder = ZModToECPolynomialField.getInstance(ecF2m, 10);

		Element message = encoder.getDomain().getElementFrom(278);
		Element encMessage = encoder.encode(message);
		Element decMessage = encoder.decode(encMessage);

		System.out.println(message);
		System.out.println(decMessage);
	}

	public static void main(final String[] args) {
		Example.runExamples();
	}

}

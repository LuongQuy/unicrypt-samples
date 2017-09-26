/*
 * UniCrypt
 *
 *  UniCrypt(tm) : Cryptographical framework allowing the implementation of cryptographic protocols e.g. e-voting
 *  Copyright (C) 2014 Bern University of Applied Sciences (BFH), Research Institute for
 *  Security in the Information Society (RISIS), E-Voting Group (EVG)
 *  Quellgasse 21, CH-2501 Biel, Switzerland
 *
 *  Licensed under Dual License consisting of:
 *  1. GNU Affero General Public License (AGPL) v3
 *  and
 *  2. Commercial license
 *
 *
 *  1. This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *  2. Licensees holding valid commercial licenses for UniCrypt may use this file in
 *   accordance with the commercial license agreement provided with the
 *   Software or, alternatively, in accordance with the terms contained in
 *   a written agreement between you and Bern University of Applied Sciences (BFH), Research Institute for
 *   Security in the Information Society (RISIS), E-Voting Group (EVG)
 *   Quellgasse 21, CH-2501 Biel, Switzerland.
 *
 *
 *   For further information contact <e-mail: unicrypt@bfh.ch>
 *
 *
 * Redistributions of files must retain the above copyright notice.
 */
package ch.bfh.unicrypt.math.algebra.additive;

import ch.bfh.unicrypt.Example;
import ch.bfh.unicrypt.math.algebra.additive.classes.ECPolynomialElement;
import ch.bfh.unicrypt.math.algebra.additive.classes.ECPolynomialField;
import ch.bfh.unicrypt.math.algebra.additive.classes.ECZModElement;
import ch.bfh.unicrypt.math.algebra.additive.classes.ECZModPrime;
import ch.bfh.unicrypt.math.algebra.additive.parameters.ECPolynomialFieldParameters;
import ch.bfh.unicrypt.math.algebra.additive.parameters.ECZModPrimeParameters;
import java.math.BigInteger;

/**
 *
 * @author C. Lutz
 * @author R. Haenni
 */
public class ECGroupExample {

	// Example with StandardECZModPrime
	public static void example1() throws Exception {
		ECZModPrimeParameters[] allParams = {
			ECZModPrimeParameters.SECP160k1,
			ECZModPrimeParameters.SECP160r1,
			ECZModPrimeParameters.SECP160r2,
			ECZModPrimeParameters.SECP192k1,
			ECZModPrimeParameters.SECP192r1,
			ECZModPrimeParameters.SECP224k1,
			ECZModPrimeParameters.SECP224r1,
			ECZModPrimeParameters.SECP256k1,
			ECZModPrimeParameters.SECP256r1,
			ECZModPrimeParameters.SECP384r1,
			ECZModPrimeParameters.SECP521r1
		};
		for (ECZModPrimeParameters params : allParams) {
			ECZModPrime ec = ECZModPrime.getInstance(params);
			Example.printLine(ec);

			// Result should be infinity element
			ECZModElement generator = ec.getDefaultGenerator();
			BigInteger order = ec.getOrder();
			Example.printLine(generator.selfApply(order));
		}
	}

	public static void example2() throws Exception {
		ECPolynomialField ec = ECPolynomialField.getInstance(ECPolynomialFieldParameters.SECT113r1);
		ECPolynomialElement r = ec.getRandomElement();
		Example.printLine(r.getY());
		Example.printLine(r.invert().getY());
		Example.printLine(r.getY());
		Example.printLine(ec.getDefaultGenerator());
		Example.printLine(ec.getDefaultGenerator().invert());
	}

	// Example with StandardECPolynomialField
	public static void example3() throws Exception {
		ECPolynomialFieldParameters[] allParams = {
			ECPolynomialFieldParameters.SECT113r1,
			ECPolynomialFieldParameters.SECT163k1,
			ECPolynomialFieldParameters.SECT163r1,
			ECPolynomialFieldParameters.SECT163r2,
			ECPolynomialFieldParameters.SECT193r1,
			ECPolynomialFieldParameters.SECT193r2,
			ECPolynomialFieldParameters.SECT233k1,
			ECPolynomialFieldParameters.SECT233r1,
			ECPolynomialFieldParameters.SECT239k1,
			ECPolynomialFieldParameters.SECT283k1,
			ECPolynomialFieldParameters.SECT409k1,
			ECPolynomialFieldParameters.SECT409r1,
			ECPolynomialFieldParameters.SECT571k1,
			ECPolynomialFieldParameters.SECT571r1
		};
		for (ECPolynomialFieldParameters params : allParams) {
			ECPolynomialField ec = ECPolynomialField.getInstance(params);
			ECPolynomialElement generator = ec.getDefaultGenerator();

			ECPolynomialElement m = ec.getRandomElement();
			ECPolynomialElement m_generator = m.add(generator);

			BigInteger order = ec.getOrder();

			Example.printLine("Message" + m.selfApply(order));
			Example.printLine("Message plus Generator" + m_generator.add(generator).selfApply(order));
			Example.printLine("Gen " + generator.selfApply(order));

			// Result should be Infinity element
		}
	}

	public static void main(final String[] args) {
		Example.runExamples();
	}

}

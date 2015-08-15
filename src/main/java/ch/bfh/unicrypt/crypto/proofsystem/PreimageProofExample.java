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
package ch.bfh.unicrypt.crypto.proofsystem;

import ch.bfh.unicrypt.Example;
import ch.bfh.unicrypt.crypto.keygenerator.interfaces.KeyPairGenerator;
import ch.bfh.unicrypt.crypto.proofsystem.challengegenerator.classes.FiatShamirSigmaChallengeGenerator;
import ch.bfh.unicrypt.crypto.proofsystem.challengegenerator.interfaces.SigmaChallengeGenerator;
import ch.bfh.unicrypt.crypto.proofsystem.classes.PlainPreimageProofSystem;
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme;
import ch.bfh.unicrypt.helper.factorization.SafePrime;
import ch.bfh.unicrypt.helper.math.Alphabet;
import ch.bfh.unicrypt.math.algebra.concatenative.classes.StringMonoid;
import ch.bfh.unicrypt.math.algebra.general.classes.Pair;
import ch.bfh.unicrypt.math.algebra.general.classes.Triple;
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple;
import ch.bfh.unicrypt.math.algebra.general.interfaces.CyclicGroup;
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element;
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime;
import ch.bfh.unicrypt.math.function.classes.CompositeFunction;
import ch.bfh.unicrypt.math.function.classes.GeneratorFunction;
import ch.bfh.unicrypt.math.function.classes.InvertFunction;
import ch.bfh.unicrypt.math.function.classes.MultiIdentityFunction;
import ch.bfh.unicrypt.math.function.classes.ProductFunction;
import ch.bfh.unicrypt.math.function.interfaces.Function;

/**
 *
 * @author Rolf Haenni <rolf.haenni@bfh.ch>
 */
public class PreimageProofExample {

	public static void example1() {

		// Create cyclic group G_q (modulo 20 bits) and get default generator
		CyclicGroup cyclicGroup = GStarModSafePrime.getInstance(SafePrime.getRandomInstance(20));
		Element generator = cyclicGroup.getDefaultGenerator();

		// Create ElGamal encryption scheme
		ElGamalEncryptionScheme elGamal = ElGamalEncryptionScheme.getInstance(generator);

		// Generate keys
		KeyPairGenerator kpg = elGamal.getKeyPairGenerator();
		Element privateKey = kpg.generatePrivateKey();
		Element publicKey = kpg.generatePublicKey(privateKey);

		// Generate proof generator
		Function function = kpg.getPublicKeyGenerationFunction();
		PlainPreimageProofSystem pg = PlainPreimageProofSystem.getInstance(function);

		// Generate and verify proof
		Triple proof = pg.generate(privateKey, publicKey);
		boolean result = pg.verify(proof, publicKey);

		Example.printLine("Cyclic Group", cyclicGroup);
		Example.printLine("Generator", generator);
		Example.printLines("Keys", privateKey, publicKey);
		Example.printLine("Proof", proof);
		Example.printLine("Check", result);
	}

	/**
	 * pi = NIZKP{(x) : y = g^x ∧ (∧_i b_i = a_i^{−x} )}.
	 */
	public static void example2() {

		// Setup
		CyclicGroup cyclicGroup = GStarModSafePrime.getInstance(SafePrime.getRandomInstance(256));
		Element g = cyclicGroup.getDefaultGenerator();

		Element x = cyclicGroup.getZModOrder().getRandomElement();
		Element y = g.selfApply(x);

		int size = 5;
		Element[] as = new Element[size];
		Element[] bs = new Element[size];
		Function[] fs = new Function[size];
		for (int i = 0; i < size; i++) {
			as[i] = cyclicGroup.getRandomElement();
			bs[i] = as[i].selfApply(x.invert());
			fs[i] = GeneratorFunction.getInstance(as[i]);
		}

		// Create proof function
		Function f = CompositeFunction.getInstance(
			   MultiIdentityFunction.getInstance(cyclicGroup.getZModOrder(), 2),
			   ProductFunction.getInstance(
					  GeneratorFunction.getInstance(g),
					  CompositeFunction.getInstance(
							 InvertFunction.getInstance(cyclicGroup.getZModOrder()),
							 MultiIdentityFunction.getInstance(cyclicGroup.getZModOrder(), size),
							 ProductFunction.getInstance(fs))));

		// Private and public input and prover id
		Element privateInput = x;
		Pair publicInput = Pair.getInstance(y, Tuple.getInstance(bs));
		Element proverId = StringMonoid.getInstance(Alphabet.BASE64).getElement("Prover1");

		// Create challenge generator and prood system
		SigmaChallengeGenerator challengeGenerator = FiatShamirSigmaChallengeGenerator.getInstance(cyclicGroup.getZModOrder(), proverId);
		PlainPreimageProofSystem proofSystem = PlainPreimageProofSystem.getInstance(challengeGenerator, f);

		// Generate and verify proof
		Triple proof = proofSystem.generate(privateInput, publicInput);
		boolean result = proofSystem.verify(proof, publicInput);

		Example.printLine("Proof", proof);
		Example.printLine("Check", result);
	}

	public static void main(final String[] args) {
		Example.runExamples();
	}

}

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
package ch.bfh.unicrypt.general;

import ch.bfh.unicrypt.Example;
import ch.bfh.unicrypt.crypto.mixer.classes.ReEncryptionMixer;
import ch.bfh.unicrypt.crypto.proofsystem.challengegenerator.classes.FiatShamirSigmaChallengeGenerator;
import ch.bfh.unicrypt.crypto.proofsystem.challengegenerator.classes.MultiValuesNonInteractiveChallengeGenerator;
import ch.bfh.unicrypt.crypto.proofsystem.challengegenerator.interfaces.ChallengeGenerator;
import ch.bfh.unicrypt.crypto.proofsystem.challengegenerator.interfaces.SigmaChallengeGenerator;
import ch.bfh.unicrypt.crypto.proofsystem.classes.ElGamalEncryptionValidityProofSystem;
import ch.bfh.unicrypt.crypto.proofsystem.classes.PermutationCommitmentProofSystem;
import ch.bfh.unicrypt.crypto.proofsystem.classes.PlainPreimageProofSystem;
import ch.bfh.unicrypt.crypto.proofsystem.classes.ReEncryptionShuffleProofSystem;
import ch.bfh.unicrypt.crypto.schemes.commitment.classes.PermutationCommitmentScheme;
import ch.bfh.unicrypt.crypto.schemes.encryption.classes.ElGamalEncryptionScheme;
import ch.bfh.unicrypt.helper.math.Alphabet;
import ch.bfh.unicrypt.helper.prime.SafePrime;
import ch.bfh.unicrypt.helper.random.deterministic.DeterministicRandomByteSequence;
import ch.bfh.unicrypt.math.algebra.concatenative.classes.StringMonoid;
import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZModElement;
import ch.bfh.unicrypt.math.algebra.general.classes.Pair;
import ch.bfh.unicrypt.math.algebra.general.classes.PermutationElement;
import ch.bfh.unicrypt.math.algebra.general.classes.ProductGroup;
import ch.bfh.unicrypt.math.algebra.general.classes.Subset;
import ch.bfh.unicrypt.math.algebra.general.classes.Triple;
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple;
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element;
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarMod;
import ch.bfh.unicrypt.math.algebra.multiplicative.classes.GStarModSafePrime;
import ch.bfh.unicrypt.math.function.classes.GeneratorFunction;
import ch.bfh.unicrypt.math.function.interfaces.Function;

/**
 *
 * @author philipp
 */
public class MixAndProofExample {

	// CHALLENGE GENERATOR
	public static void example1() {

		// Setup
		final GStarMod G_q = GStarModSafePrime.getInstance(167);
		final StringMonoid sm = StringMonoid.getInstance(Alphabet.BASE64);
		final Element proverId = sm.getElement("Prover1");

		// Challenge Generator
		//=====================
		// Create a non-interactive challenge generator that on input <StringElement> returns
		// 10 ZMod elements
		ChallengeGenerator cg = MultiValuesNonInteractiveChallengeGenerator.getInstance(G_q.getZModOrder(), 10);

		// Generate challenge
		Tuple challenges = (Tuple) cg.generate(sm.getElement("inputX"));
		Example.printLine("Challenges", challenges);

		// Sigma Challenge Generator
		//===========================
		// Proof function
		final Function f = GeneratorFunction.getInstance(G_q.getDefaultGenerator());
		// Public input
		final Element publicInput = G_q.getRandomElement();
		// Prover's commitment
		final Element commitment = f.apply(G_q.getZModOrder().getElement(3));

		// Create non-interactive sigma challenge generator for function <f> and prover <proverId>
		SigmaChallengeGenerator scg = FiatShamirSigmaChallengeGenerator.getInstance(f, proverId);

		// Generate challenge
		ZModElement challenge = scg.generate(publicInput, commitment);
		Example.printLine("Challenge", challenge);
	}

	// PREIMAGE PROOF GENERATOR
	public static void example2() {

		// Setup
		final GStarMod G_q = GStarModSafePrime.getInstance(167);
		final StringMonoid sm = StringMonoid.getInstance(Alphabet.BASE64);
		final Element proverId = sm.getElement("Prover1");

		// Create preimage proof generator for function f
		// f: Z_q -> G_q
		//    y = f(x) = 4^x
		//
		// - Create proof function
		GeneratorFunction f = GeneratorFunction.getInstance(G_q.getElement(4));
		// - Create sigma challenge generator
		SigmaChallengeGenerator scg = FiatShamirSigmaChallengeGenerator.getInstance(f, proverId);
		// - Create preimage proof generator
		PlainPreimageProofSystem pg = PlainPreimageProofSystem.getInstance(scg, f);

		// Private and public input
		Element privateInput = G_q.getZModOrder().getElement(3);
		Element publicInput = G_q.getElement(64);

		// Generate proof
		Triple proof = pg.generate(privateInput, publicInput);

		// Verify proof
		boolean v = pg.verify(proof, publicInput);
		Example.printLine("Proof is valid", v);
	}

	// ELGAMAL ENCRYPTION VALIDITY PROOF
	public static void example3() {

		// Setup
		final GStarMod G_q = GStarModSafePrime.getInstance(167);
		final StringMonoid sm = StringMonoid.getInstance(Alphabet.BASE64);
		final Element proverId = sm.getElement("Prover1");

		// Create ElGamal encryption validity proof
		//    Plaintexts: {4, 2, 8, 16}, g = 2, pk = 4
		//    Valid tuple: (2^3, 4^3*2) = (8, 128)
		//
		// - Create ElGamal encryption scheme
		ElGamalEncryptionScheme elGamalES = ElGamalEncryptionScheme.getInstance(G_q.getElement(2));
		Element publicKey = G_q.getElement(4);
		// - Create subset of valid plaintexts
		Subset plaintexts = Subset.getInstance(G_q, new Element[]{G_q.getElement(4), G_q.getElement(2), G_q.getElement(8), G_q.getElement(16)});
		// - Create ElGamal encryption validity proof generator (a non-inteactive sigma challenge generator
		//   is created implicitly
		ElGamalEncryptionValidityProofSystem pg = ElGamalEncryptionValidityProofSystem.getInstance(proverId, elGamalES, publicKey, plaintexts);

		// Public input
		Pair publicInput = Pair.getInstance(G_q.getElement(8), G_q.getElement(128));

		// Private input
		Element secret = G_q.getZModOrder().getElement(3);
		int index = 1;
		Pair privateInput = pg.createPrivateInput(secret, index);

		// Generate proof
		Triple proof = pg.generate(privateInput, publicInput);

		// Verify proof
		boolean v = pg.verify(proof, publicInput);
		Example.printLine("Proof is valid", v);
	}

	// MIXER
	public static void example4() {

		// Setup
		final GStarMod G_q = GStarModSafePrime.getInstance(167);

		// Create a few ciphertexts at random
		Tuple ciphertexts = ProductGroup.getInstance(ProductGroup.getInstance(G_q, 2), 5).getRandomElement();
		int size = ciphertexts.getArity();

		// Create ElGamal encryption scheme
		ElGamalEncryptionScheme elGamalES = ElGamalEncryptionScheme.getInstance(G_q.getElement(2));
		Element publicKey = G_q.getElement(4);

		// Create re-encryption mixer based on the ElGamal encryption scheme
		ReEncryptionMixer mixer = ReEncryptionMixer.getInstance(elGamalES, publicKey, size);

		// Create a random permutation
		PermutationElement permutation = mixer.getPermutationGroup().getRandomElement();

		// Create random randomizations (using a helper method of the mixer)
		Tuple randomizations = mixer.generateRandomizations();

		// Shuffle
		Tuple shuffledCiphertexts = mixer.shuffle(ciphertexts, permutation, randomizations);
		Example.printLine("Input ciphertexts ", ciphertexts);
		Example.printLine("Output ciphertexts", shuffledCiphertexts);
	}

	// COMPLETE SHUFFLE
	public static void example5() {

		// S E T U P
		//-----------
		// Create cyclic group
		final GStarModSafePrime G_q = GStarModSafePrime.getInstance(SafePrime.getRandomInstance(160));
		// Create generator based on the default reference random byte sequence (-> independent generators)
		final Element g = G_q.getIndependentGenerators(DeterministicRandomByteSequence.getInstance()).get(0);

		// Set size
		final int size = 10;

		// Create ElGamal encryption scheme
		ElGamalEncryptionScheme elGamalES = ElGamalEncryptionScheme.getInstance(g);
		Element publicKey = G_q.getRandomElement();

		// Create ciphertexts at random
		Tuple ciphertexts = ProductGroup.getInstance(elGamalES.getEncryptionSpace(), size).getRandomElement();

		// S H U F F L E
		//---------------
		// Create mixer
		ReEncryptionMixer mixer = ReEncryptionMixer.getInstance(elGamalES, publicKey, size);
		// Create a random permutation
		PermutationElement permutation = mixer.getPermutationGroup().getRandomElement();
		// Create random randomizations
		Tuple randomizations = mixer.generateRandomizations();
		// Shuffle
		Tuple shuffledCiphertexts = mixer.shuffle(ciphertexts, permutation, randomizations);

		// P R O O F
		//-----------
		//
		// 1. Permutation Proof
		//----------------------
		// Create permutation commitment
		PermutationCommitmentScheme pcs = PermutationCommitmentScheme.getInstance(G_q, size);
		Tuple permutationCommitmentRandomizations = pcs.getRandomizationSpace().getRandomElement();
		Tuple permutationCommitment = pcs.commit(permutation, permutationCommitmentRandomizations);

		// Create permutation commitment proof generator (a non-interactive challenge generator for the
		// e-values and a non-interactive sigma challenge generator are created implicitly, the independent
		// generators are created based on the default random reference byte sequence)
		PermutationCommitmentProofSystem pcpg = PermutationCommitmentProofSystem.getInstance(G_q, size);

		// Private and public input
		Pair privateInput1 = Pair.getInstance(permutation, permutationCommitmentRandomizations);
		Element publicInput1 = permutationCommitment;

		// Generate permutation commitment proof
		Tuple proofPermutation = pcpg.generate(privateInput1, publicInput1);

		// 2. Shuffle Proof
		//------------------
		// Create shuffle proof generator (... -> see permutatin commitment proof generator)
		ReEncryptionShuffleProofSystem spg = ReEncryptionShuffleProofSystem.getInstance(size, elGamalES, publicKey);

		// Private and public input
		Triple privateInput2 = Triple.getInstance(permutation, permutationCommitmentRandomizations, randomizations);
		Triple publicInput2 = Triple.getInstance(permutationCommitment, ciphertexts, shuffledCiphertexts);

		// Generate shuffle proof
		Tuple proofShuffle = spg.generate(privateInput2, publicInput2);

		// V E R I F Y
		//-------------
		// Verify permutation commitment proof
		boolean vPermutation = pcpg.verify(proofPermutation, publicInput1);

		// Verify shuffle proof
		boolean vShuffle = spg.verify(proofShuffle, publicInput2);

		// Verify equality of permutation commitments
		boolean vPermutationCommitments = publicInput1.isEquivalent(publicInput2.getFirst());

		if (vPermutation && vShuffle && vPermutationCommitments) {
			Example.printLine("Proof is valid!");
		} else {
			Example.printLine("Proof is NOT valid!");
		}
	}

	public static void main(final String[] args) {
		Example.runExamples();
	}

}

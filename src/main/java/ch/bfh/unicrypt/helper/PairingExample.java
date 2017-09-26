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
package ch.bfh.unicrypt.helper;

import ch.bfh.unicrypt.Example;
import ch.bfh.unicrypt.helper.aggregator.classes.BigIntegerAggregator;
import ch.bfh.unicrypt.helper.aggregator.interfaces.Aggregator;
import ch.bfh.unicrypt.helper.math.MathUtil;
import ch.bfh.unicrypt.helper.tree.Tree;
import java.math.BigInteger;

/**
 *
 * @author Rolf Haenni <rolf.haenni@bfh.ch>
 */
public class PairingExample {

	public static void example1() {

		// Perform pairing and unpairing
		BigInteger p = MathUtil.pair(4, 5);
		BigInteger[] u = MathUtil.unpair(p);

		Example.printLine("Paired value", p);
		Example.printLines("Unpaired values", u);
	}

	public static void example2() {

		// Perform pairing and unpairing of multiple values
		BigInteger p = MathUtil.pairWithSize(12, 29, 8);
		BigInteger[] u = MathUtil.unpairWithSize(p);

		Example.printLine("Paired values", p);
		Example.printLine("Unpaired values", u);
	}

	public static void example3() {

		// Create some a tree of integers
		Tree<BigInteger> l1 = Tree.getInstance(new BigInteger("12"));
		Tree<BigInteger> l2 = Tree.getInstance(new BigInteger("4"));
		Tree<BigInteger> l3 = Tree.getInstance(new BigInteger("5"));
		Tree<BigInteger> l4 = Tree.getInstance(new BigInteger("8"));
		Tree<BigInteger> node = Tree.getInstance(l2, l3);
		Tree<BigInteger> tree = Tree.getInstance(l1, node, l4);

		// Perform pairing and unpairing using a the default aggregator
		Aggregator<BigInteger> aggregator = BigIntegerAggregator.getInstance();
		BigInteger result = aggregator.aggregate(tree);
		Tree<BigInteger> t = aggregator.disaggregate(result);

		Example.printLine("Paired values", result);
		Example.printLine("Unpaired values", t);
	}

	public static void example4() {

		// Perform folding and unfolding
		BigInteger f = MathUtil.fold(-29);
		BigInteger u = MathUtil.unfold(f);

		Example.printLine("Folded value", f);
		Example.printLine("Unfolded value", u);
	}

	public static void main(final String[] args) {
		Example.runExamples();
	}

}

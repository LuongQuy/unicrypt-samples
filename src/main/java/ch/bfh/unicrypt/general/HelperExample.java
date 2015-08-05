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
import ch.bfh.unicrypt.helper.aggregator.classes.ByteArrayAggregator;
import ch.bfh.unicrypt.helper.array.classes.ByteArray;
import ch.bfh.unicrypt.helper.hash.HashAlgorithm;
import ch.bfh.unicrypt.helper.tree.Tree;

/**
 *
 * @author Rolf Haenni <rolf.haenni@bfh.ch>
 */
public class HelperExample {

	public static void example1() {

		// Define byte arrays
		ByteArray b1 = ByteArray.getInstance("F1|62|23|C4|25|86|A7");
		ByteArray b2 = ByteArray.getInstance(10, -54, 120);
		ByteArray b3 = ByteArray.getRandomInstance(7);

		// Perform operations
		ByteArray b4 = b1.extract(2, 4);
		ByteArray b5 = b1.append(b2);
		ByteArray b6 = b1.xor(b3);

		// Compute hash values
		ByteArray b7 = b1.getHashValue();
		ByteArray b8 = b1.getHashValue(HashAlgorithm.SHA256);

		// Print results
		Example.printLines("ByteArrays", b1, b2, b3);
		Example.printLine("Extract", b4);
		Example.printLine("Append ", b5);
		Example.printLine("XOR    ", b6);
		Example.printLine("SHA-256", b7);
		Example.printLine("MD5    ", b8);
	}

	public static void example2() {

		// Define multiple byte tree leaves
		Tree<ByteArray> t1 = Tree.getInstance(ByteArray.getInstance("1A|43"));
		Tree<ByteArray> t2 = Tree.getInstance(ByteArray.getInstance("71|B2|29"));
		Tree<ByteArray> t3 = Tree.getInstance(ByteArray.getInstance("2F"));
		Tree<ByteArray> t4 = Tree.getInstance(ByteArray.getInstance("C4|B2"));

		// Combine bt3, bt4
		Tree<ByteArray> t5 = Tree.getInstance(t3, t4);

		// Combine bt1, bt2, bt5
		Tree<ByteArray> tree = Tree.getInstance(t1, t2, t5);

		// Convert ByteArrayTree to ByteArray
		ByteArray byteArray = tree.aggregate(ByteArrayAggregator.getInstance());

		// Convert ByteArray to ByteTree
		Tree<ByteArray> recoveredTree = Tree.getInstance(byteArray, ByteArrayAggregator.getInstance());

		// Print results
		Example.printLines("Nodes", t1, t2, t3, t4, t5);
		Example.printLine("Tree     ", tree);
		Example.printLine("ByteArray", byteArray);
		Example.printLine("Recovered", recoveredTree);
	}

	public static void main(final String[] args) {
		Example.runExamples();
	}

}

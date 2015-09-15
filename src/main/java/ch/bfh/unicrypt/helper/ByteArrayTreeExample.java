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
import ch.bfh.unicrypt.exception.UniCryptException;
import ch.bfh.unicrypt.helper.aggregator.classes.ByteArrayAggregator;
import ch.bfh.unicrypt.helper.array.classes.ByteArray;
import ch.bfh.unicrypt.helper.converter.classes.ConvertMethod;
import ch.bfh.unicrypt.helper.tree.Tree;
import ch.bfh.unicrypt.math.algebra.dualistic.classes.N;
import ch.bfh.unicrypt.math.algebra.general.classes.Pair;
import ch.bfh.unicrypt.math.algebra.general.classes.PermutationGroup;
import ch.bfh.unicrypt.math.algebra.general.classes.ProductSet;
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple;
import ch.bfh.unicrypt.math.algebra.general.interfaces.Element;

/**
 *
 * @author Reto E. Koenig <reto.koenig@bfh.ch>
 */
public class ByteArrayTreeExample {

	public static void example1() {

		// Define multiple byte tree leaves
		Tree<ByteArray> l1 = Tree.getInstance(ByteArray.getInstance(1));
		Tree<ByteArray> l2 = Tree.getInstance(ByteArray.getInstance(2));
		Tree<ByteArray> l3 = Tree.getInstance(ByteArray.getInstance(3));
		Tree<ByteArray> l4 = Tree.getInstance(ByteArray.getInstance(4));
		Tree<ByteArray> l5 = Tree.getInstance(ByteArray.getInstance(1, 0));

		// Combine l1 to l3
		Tree<ByteArray> n1 = Tree.getInstance(l1, l2, l3);

		// Combine l4 and l5
		Tree<ByteArray> n2 = Tree.getInstance(l4, l5);

		// Combine n1 and n2
		Tree<ByteArray> tree = Tree.getInstance(n1, n2);
		ByteArray byteArray = tree.aggregate(ByteArrayAggregator.getInstance());

		Example.printLines("Leaves", l1, l2, l3, l4, l5);
		Example.printLines("Nodes", n1, n2);
		Example.printLines("Tree/ByteArray", tree, byteArray);
	}

	public static void example2() {

		// The same as Example 1, but using UniCrypt elements
		N naturalNumbers = N.getInstance();

		// Define multiple natural numbers
		Element e1 = naturalNumbers.getElement(1);
		Element e2 = naturalNumbers.getElement(2);
		Element e3 = naturalNumbers.getElement(3);
		Element e4 = naturalNumbers.getElement(4);
		Element e5 = naturalNumbers.getElement(256);

		// Combine e1 to e3
		Tuple t1 = Tuple.getInstance(e1, e2, e3);
		Tree<ByteArray> tree1 = t1.convertTo(ConvertMethod.getInstance());

		// Combine e4 and e5
		Tuple t2 = Tuple.getInstance(e4, e5);
		Tree<ByteArray> tree2 = t2.convertTo(ConvertMethod.getInstance());

		// Combine t1 and t2
		Tuple tuple = Tuple.getInstance(t1, t2);
		Tree<ByteArray> tree = tuple.convertTo(ConvertMethod.getInstance());
		ByteArray byteArray = tree.aggregate(ByteArrayAggregator.getInstance());

		Example.printLines("Elements", e1, e2, e3, e4, e5);
		Example.printLines("Tuples/Nodes", t1, tree1, t2, tree2);
		Example.printLines("Tuple/Tree/ByteArray", tuple, tree, byteArray);
	}

	public static void example3() {

		// Same as Example 1
		Tree<ByteArray> l1 = Tree.getInstance(ByteArray.getInstance(1));
		Tree<ByteArray> l2 = Tree.getInstance(ByteArray.getInstance(2));
		Tree<ByteArray> l3 = Tree.getInstance(ByteArray.getInstance(3));
		Tree<ByteArray> l4 = Tree.getInstance(ByteArray.getInstance(4));
		Tree<ByteArray> l5 = Tree.getInstance(ByteArray.getInstance(1, 0));
		Tree<ByteArray> n1 = Tree.getInstance(l1, l2, l3);
		Tree<ByteArray> n2 = Tree.getInstance(l4, l5);
		Tree<ByteArray> tree = Tree.getInstance(n1, n2);
		ByteArray byteArray = tree.aggregate(ByteArrayAggregator.getInstance());

		// Reconstruct byte tree from byte array
		Tree<ByteArray> result = Tree.getInstance(byteArray, ByteArrayAggregator.getInstance());

		Example.printLine("Tree", tree);
		Example.printLine("ByteArray", byteArray);
		Example.printLine("Result", result);
	}

	public static void example4() {

		// Same as Example 2
		N nSet = N.getInstance();
		Element e1 = nSet.getElement(1);
		Element e2 = nSet.getElement(2);
		Element e3 = nSet.getElement(3);
		Element e4 = nSet.getElement(4);
		Element e5 = nSet.getElement(256);
		Tuple t1 = Tuple.getInstance(e1, e2, e3);
		Tuple t2 = Tuple.getInstance(e4, e5);
		Tuple tuple = Tuple.getInstance(t1, t2);
		Tree<ByteArray> tree = tuple.convertTo(ConvertMethod.getInstance());
		ByteArray byteArray = tree.aggregate(ByteArrayAggregator.getInstance());

		// Reconstruct tuple from byte array
		ProductSet set = tuple.getSet();
		Tree<ByteArray> recTree = Tree.getInstance(byteArray, ByteArrayAggregator.getInstance());
		Tuple recTuple;
		try {
			recTuple = set.getElementFrom(recTree, ConvertMethod.getInstance());
			Example.printLines("Tuples", tuple, recTuple);
			Example.printLines("Trees", tree, recTree);
		} catch (UniCryptException ex) {
		}
	}

	public static void example5() {

		// Construct two permutation elements
		PermutationGroup group = PermutationGroup.getInstance(5);
		Element p1 = group.getRandomElement();
		Element p2 = group.getRandomElement();

		// Construct pair (p1,p2) and convert to byte tree
		Pair pair = Pair.getInstance(p1, p2);
		Tree<ByteArray> tree = pair.convertTo(ConvertMethod.getInstance());
		ByteArray byteArray = tree.aggregate(ByteArrayAggregator.getInstance());

		// Reconstruct tuple from byte array
		ProductSet set = pair.getSet();
		Tree<ByteArray> recTree = Tree.getInstance(byteArray, ByteArrayAggregator.getInstance());
		Tuple recPair;
		try {
			recPair = set.getElementFrom(recTree, ConvertMethod.getInstance());
			Example.printLine("Pair", pair);
			Example.printLines("Tree/ByteArray", tree, byteArray);
			Example.printLines("Recovered Tree/Pair", recTree, recPair);
		} catch (UniCryptException ex) {
		}

	}

	public static void main(String[] args) {
		Example.runExamples();
	}

}

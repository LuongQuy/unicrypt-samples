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
import ch.bfh.unicrypt.UniCryptException;
import ch.bfh.unicrypt.helper.aggregator.classes.ByteArrayAggregator;
import ch.bfh.unicrypt.helper.aggregator.interfaces.Aggregator;
import ch.bfh.unicrypt.helper.array.classes.ByteArray;
import ch.bfh.unicrypt.helper.converter.classes.ConvertMethod;
import ch.bfh.unicrypt.helper.converter.classes.bytearray.BigIntegerToByteArray;
import ch.bfh.unicrypt.helper.converter.classes.bytearray.StringToByteArray;
import ch.bfh.unicrypt.helper.math.Alphabet;
import ch.bfh.unicrypt.helper.math.Permutation;
import ch.bfh.unicrypt.helper.tree.Tree;
import ch.bfh.unicrypt.math.algebra.concatenative.classes.StringElement;
import ch.bfh.unicrypt.math.algebra.concatenative.classes.StringMonoid;
import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZMod;
import ch.bfh.unicrypt.math.algebra.dualistic.classes.ZModElement;
import ch.bfh.unicrypt.math.algebra.general.classes.PermutationElement;
import ch.bfh.unicrypt.math.algebra.general.classes.PermutationGroup;
import ch.bfh.unicrypt.math.algebra.general.classes.ProductSet;
import ch.bfh.unicrypt.math.algebra.general.classes.Tuple;
import java.nio.ByteOrder;
import java.nio.charset.Charset;

/**
 *
 * @author Rolf Haenni <rolf.haenni@bfh.ch>
 */
public class ConvertMethodExample {

	public static void example1() {

		// String converter
		StringToByteArray stringConverter = StringToByteArray.getInstance(Charset.forName("UTF-8"));

		// BigIntegerToByteArray
		BigIntegerToByteArray bigIntegerConverter = BigIntegerToByteArray.getInstance(ByteOrder.LITTLE_ENDIAN);

		// Three convert methods
		ConvertMethod<ByteArray> convertMethod1 = ConvertMethod.getInstance();
		ConvertMethod<ByteArray> convertMethod2 = ConvertMethod.getInstance(bigIntegerConverter);
		ConvertMethod<ByteArray> convertMethod3 = ConvertMethod.getInstance(stringConverter);
		ConvertMethod<ByteArray> convertMethod4 = ConvertMethod.getInstance(stringConverter, bigIntegerConverter);

		// Aggregator
		Aggregator<ByteArray> aggregator = ByteArrayAggregator.getInstance();

		// String monoid
		StringMonoid set = StringMonoid.getInstance(Alphabet.DECIMAL);

		// String element
		StringElement element = set.getElement("1234");

		Example.printLine(set);
		Example.printLine(element);

		Example.printLine("BigInteger", element.convertToBigInteger());

		// Converting the element to byte array (forth and back)
		Example.printLabelLine("CONVERSION TO BYTE ARRAY");

		try {
			ByteArray byteArray;
			byteArray = element.convertToByteArray();
			Example.printLine(set.getElementFrom(byteArray), byteArray);

			byteArray = element.convertTo(stringConverter);
			Example.printLine(set.getElementFrom(byteArray, stringConverter), byteArray);

			byteArray = element.convertTo(convertMethod1, aggregator);
			Example.printLine(set.getElementFrom(byteArray, convertMethod1, aggregator), byteArray);

			byteArray = element.convertTo(convertMethod2, aggregator);
			Example.printLine(set.getElementFrom(byteArray, convertMethod2, aggregator), byteArray);

			byteArray = element.convertTo(convertMethod3, aggregator);
			Example.printLine(set.getElementFrom(byteArray, convertMethod3, aggregator), byteArray);

			byteArray = element.convertTo(convertMethod4, aggregator);
			Example.printLine(set.getElementFrom(byteArray, convertMethod4, aggregator), byteArray);
		} catch (UniCryptException ex) {
		}

		// Converting the element to byte tree (forth and back)
		Example.printLabelLine("CONVERSION TO BYTE TREE");

		try {
			Tree<ByteArray> tree;
			tree = element.convertTo(ConvertMethod.getInstance());
			Example.printLine(set.getElementFrom(tree, ConvertMethod.getInstance()), tree);

			ByteArray byteArray = element.convertTo(stringConverter);
			Example.printLine(set.getElementFrom(byteArray, stringConverter), byteArray);

			tree = element.convertTo(convertMethod1);
			Example.printLine(set.getElementFrom(tree, convertMethod1), tree);

			tree = element.convertTo(convertMethod2);
			Example.printLine(set.getElementFrom(tree, convertMethod2), tree);

			tree = element.convertTo(convertMethod3);
			Example.printLine(set.getElementFrom(tree, convertMethod3), tree);

			tree = element.convertTo(convertMethod4);
			Example.printLine(set.getElementFrom(tree, convertMethod4), tree);
		} catch (UniCryptException ex) {
		}

	}

	public static void example2() {

		// Two converters
		StringToByteArray stringConverter = StringToByteArray.getInstance(Charset.forName("UTF-8"));
		BigIntegerToByteArray bigIntegerConverter = BigIntegerToByteArray.getInstance(ByteOrder.LITTLE_ENDIAN);

		// Two ConvertMethods
		ConvertMethod convertMethod1 = ConvertMethod.getInstance(stringConverter);
		ConvertMethod convertMethod2 = ConvertMethod.getInstance(stringConverter, bigIntegerConverter);

		// Three sets
		StringMonoid s1 = StringMonoid.getInstance(Alphabet.DECIMAL);
		ZMod s2 = ZMod.getInstance(33);
		PermutationGroup s3 = PermutationGroup.getInstance(5);

		// Three elements
		StringElement e1 = s1.getElement("1234");
		ZModElement e2 = s2.getElement(5);
		PermutationElement e3 = s3.getElement(Permutation.getInstance(5));

		// Tuple and ProductSet
		ProductSet productSet = ProductSet.getInstance(s1, s2, s3);
		Tuple tuple = productSet.getElement(e1, e2, e3);

		Example.printLine(e1, e2, e3);
		Example.printLine(tuple);

		Example.printLine("BigInteger", tuple.convertToBigInteger());

		// Converting the tuple to byte array forth and back
		Example.printLabelLine("CONVERSION TO BYTE ARRAY");

		try {
			ByteArray byteArray;
			byteArray = tuple.convertToByteArray();
			Example.printLine(productSet.getElementFrom(byteArray), byteArray);

			byteArray = tuple.convertTo(convertMethod1, ByteArrayAggregator.getInstance());
			Example.printLine(productSet.getElementFrom(byteArray, convertMethod1, ByteArrayAggregator.getInstance()), byteArray);

			byteArray = tuple.convertTo(convertMethod2, ByteArrayAggregator.getInstance());
			Example.printLine(productSet.getElementFrom(byteArray, convertMethod2, ByteArrayAggregator.getInstance()), byteArray);
		} catch (UniCryptException ex) {
		}

		// Converting the tuple to byte tree forth and back
		Example.printLabelLine("CONVERSION TO BYTE TREE");

		try {
			Tree<ByteArray> byteTree;
			byteTree = tuple.convertTo(ConvertMethod.getInstance());
			Example.printLine(productSet.getElementFrom(byteTree, ConvertMethod.getInstance()), byteTree);

			byteTree = tuple.convertTo(convertMethod1);
			Example.printLine(productSet.getElementFrom(byteTree, convertMethod1), byteTree);

			byteTree = tuple.convertTo(convertMethod2);
			Example.printLine(productSet.getElementFrom(byteTree, convertMethod2), byteTree);
		} catch (UniCryptException ex) {
		}

	}

	public static void main(final String[] args) {
		Example.runExamples();
	}

}

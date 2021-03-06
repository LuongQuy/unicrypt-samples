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
import ch.bfh.unicrypt.helper.array.classes.SparseArray;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Rolf Haenni <rolf.haenni@bfh.ch>
 */
public class SparseArrayExample {

	public static void example1() {

		Map<Integer, String> map = new HashMap<>();
		map.put(3, "3");
		map.put(7, "7");
		map.put(11, "11");

		SparseArray<String> sparseArray = SparseArray.getInstance("0", map);

		Example.printLine(sparseArray);
		Example.printLine(sparseArray.getLength());
		Example.printLine(sparseArray.getAllIndices());
		Example.printLine(sparseArray.shiftLeft(1));
		Example.printLine(sparseArray.shiftLeft(2));
		Example.printLine(sparseArray.shiftLeft(3));
		Example.printLine(sparseArray.shiftLeft(4));
		Example.printLine(sparseArray.shiftLeft(11));
		Example.printLine(sparseArray.shiftLeft(12));
		Example.printLine(sparseArray.shiftRight(2));
	}

	public static void example2() {

		SparseArray<Integer> a = SparseArray.getInstance(0, 0, 1, 2, 0, 4, 5, 0, 0, 8, 9, 10);

		Example.printLine(a);
		Example.printLine("Length  ", a.getLength());
		Example.printLine("Add     ", a.add(7));
		Example.printLine("Append  ", a.append(a));
		Example.printLine("Extract ", a.extract(2, 3));
		Example.printLine("ExtraxtP", a.extractPrefix(2));
		Example.printLine("ExtraxtS", a.extractSuffix(2));
		Example.printLine("ExtractR", a.extractRange(2, 8));
		Example.printLine("Insert  ", a.insertAt(5, 100));
		Example.printLine("Replace ", a.replaceAt(5, 100));
		Example.printLine("Replace ", a.replaceAt(6, 100));
		Example.printLine("Remove  ", a.removeAt(5));
		Example.printLines("Split   ", a.split(2, 4, 7));

	}

	public static void main(final String[] args) {
		Example.runExamples();
	}

}

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
import ch.bfh.unicrypt.helper.array.classes.ByteArray;
import ch.bfh.unicrypt.helper.hash.HashAlgorithm;

/**
 *
 * @author Rolf Haenni <rolf.haenni@bfh.ch>
 */
public class HashAlgoritmExample {

	public static void example1() {

		HashAlgorithm algorithm = HashAlgorithm.SHA1;
		String name = algorithm.getAlgorithmName();
		int bitLength = algorithm.getBitLength();

		ByteArray input1 = ByteArray.getInstance("01");
		ByteArray input2 = ByteArray.getInstance("7F");
		ByteArray input3 = ByteArray.getInstance("FE|FF");
		ByteArray input4 = ByteArray.getInstance("48|65|6C|6C|6F");

		ByteArray hash1 = algorithm.getHashValue(input1);
		ByteArray hash2 = algorithm.getHashValue(input2);
		ByteArray hash3 = algorithm.getHashValue(input3);
		ByteArray hash4 = algorithm.getHashValue(input4);
		ByteArray hash23 = algorithm.getHashValue(hash2.append(hash3));
		ByteArray hash1234 = algorithm.getHashValue(hash1.append(hash23).append(hash4));

		Example.printLine("Name     ", name);
		Example.printLine("BitLenght", bitLength);
		Example.printLines("Hash Values", hash1, hash2, hash3, hash4, hash23, hash1234);
	}

	public static void main(final String[] args) {
		Example.runExamples();
	}

}

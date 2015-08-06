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
import ch.bfh.unicrypt.helper.converter.classes.bytearray.BigIntegerToByteArray;
import ch.bfh.unicrypt.helper.converter.classes.bytearray.StringToByteArray;
import java.math.BigInteger;

/**
 *
 * @author Rolf Haenni <rolf.haenni@bfh.ch>
 */
public class ConverterExample {

	public static void example1() {

		// Create the default ByteOrder.BIG_ENDIAN converter
		BigIntegerToByteArray converter = BigIntegerToByteArray.getInstance();

		// Convert various integers
		ByteArray b1 = converter.convert(1);
		ByteArray b2 = converter.convert(127);
		ByteArray b3 = converter.convert(-257);

		// Reconvert the byte arrays
		BigInteger i1 = converter.reconvert(b1);
		BigInteger i2 = converter.reconvert(b2);
		BigInteger i3 = converter.reconvert(b3);

		// Show results
		Example.printLines("ByteArray", b1, b2, b3);
		Example.printLines("BigInteger", i1, i2, i3);

	}

	public static void example2() {

		// Create the default UTF-8 converter
		StringToByteArray converter = StringToByteArray.getInstance();

		// Convert various strings
		ByteArray s1 = converter.convert("");
		ByteArray s2 = converter.convert("Hello");
		ByteArray s3 = converter.convert("Voilà");

		// Reconvert the byte arrays
		String i1 = converter.reconvert(s1);
		String i2 = converter.reconvert(s2);
		String i3 = converter.reconvert(s3);

		// Show results
		Example.printLines("ByteArray", s1, s2, s3);
		Example.printLines("String", i1, i2, i3);

	}

	public static void main(final String[] args) {
		Example.runExamples();
	}

}

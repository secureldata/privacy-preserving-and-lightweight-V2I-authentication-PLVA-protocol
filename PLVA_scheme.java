import java.math.BigInteger;
import java.security.SecureRandom;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1Pairing;
import it.unisa.dia.gas.plaf.jpbc.util.math.BigIntegerUtils;

public class BGNEncryption {

	public static final String start = "start";
	public static final String end = "end";
	private PairingParameters param;
	private BigInteger r;
	private BigInteger q; // This is the private key.
	private BigInteger order;
	private SecureRandom rng;

	public PublicKey gen(int bits) {
		rng = new SecureRandom();
		TypeA1CurveGenerator a1 = new TypeA1CurveGenerator(rng, 2, bits); // Requires
																			// 2
																			// prime
		//ecc cruve																	// numbers.
		param = a1.generate();
		TypeA1Pairing pairing = new TypeA1Pairing(param);
		order = param.getBigInteger("n"); // Must extract the prime numbers for
											// both keys.
		r = param.getBigInteger("n0");
		q = param.getBigInteger("n1");
		Field<?> f = pairing.getG1();
		Element P = f.newRandomElement();
		P = P.mul(param.getBigInteger("l"));
		Element Q = f.newElement();
		Q = Q.set(P);
		Q = Q.mul(r);
		return new PublicKey(pairing, P, Q, order);
	}

	public Element encrypt(PublicKey PK, int msg) {
		BigInteger t = BigIntegerUtils.getRandom(PK.getN());
		int m = msg;
		System.out.println("Hash is " + m);
		Field<?> f = PK.getField();
		Element A = f.newElement();
		Element B = f.newElement();
		Element C = f.newElement();
		A = A.set(PK.getP());
		A = A.mul(BigInteger.valueOf(m));
		B = B.set(PK.getQ());
		B = B.mul(t);
		C = C.set(A);
		C = C.add(B);
		return C;
	}
	public Element encryptstr(PublicKey PK, String msg) {
		BigInteger t = BigIntegerUtils.getRandom(PK.getN());
		String m = msg;
		System.out.println("Hash is " + m);
		Field<?> f = PK.getField();
		Element A = f.newElement();
		Element B = f.newElement();
		Element C = f.newElement();
		A = A.set(PK.getP());
		Integer s=Integer.valueOf(m);
		A = A.mul(BigInteger.valueOf(s));
		B = B.set(PK.getQ());
		B = B.mul(t);
		C = C.set(A);
		C = C.add(B);
		return C;
	}
	public Element add(PublicKey PK, Element A, Element B) {
		BigInteger t = BigIntegerUtils.getRandom(PK.getN());
		Field<?> f = PK.getField();
		Element output = f.newElement();
		Element aux = f.newElement();
		aux.set(PK.getQ());
		aux.mul(t);
		output.set(A);
		output.add(B);
		output.add(aux);
		return output;
	}

	public Element mul(PublicKey PK, Element C, Element D) {
		BigInteger t = BigIntegerUtils.getRandom(PK.getN());

		Element T = PK.doPairing(C, D);

		Element K = PK.doPairing(PK.getQ(), PK.getQ());
		K = K.pow(t);
		return T.mul(K);
	}

	public String decryptMul(PublicKey PK, BigInteger sk, Element C) {
		Element PSK = PK.doPairing(PK.getP(), PK.getP());
		PSK.pow(sk);

		Element CSK = C.duplicate();
		CSK.pow(sk);
		Element aux = PSK.duplicate();

		BigInteger m = new BigInteger("1");
		while (!aux.isEqual(CSK)) {
			aux = aux.mul(PSK);
			m = m.add(BigInteger.valueOf(1));
		}
		return m.toString();
	}

	public String decrypt(PublicKey PK, BigInteger sk, Element C) {
		Field<?> f = PK.getField();
		Element T = f.newElement();
		Element K = f.newElement();
		Element aux = f.newElement();
		T = T.set(PK.getP());
		T = T.mul(sk);
		K = K.set(C);
		K = K.mul(sk);
		aux = aux.set(T);
		BigInteger m = new BigInteger("1");
		while (!aux.isEqual(K)) {
			// This is a brute force implementation of finding the discrete
			// logarithm.
			// Performance may be improved using algorithms such as Pollard's
			// Kangaroo.
			aux = aux.add(T);
			m = m.add(BigInteger.valueOf(1));
		}
		return m.toString();
	}
	public String StrToBinstr(String str) {
		char[] strChar = str.toCharArray();
		String result = "";
		for (int i = 0; i < strChar.length; i++) {
			result += Integer.toBinaryString(strChar[i]) + " ";
		}
		return result;
	}

	public String[] StrToStrArray(String str) {
		return str.split(" ");
	}

	public static void main(String[] args) {
		BGNEncryption b = new BGNEncryption();
		PublicKey PK = b.gen(32);
		Element Final_result;

		Element key1 = b.encryptstr(PK, "0001");
		System.out.println("Final_result: " + b.StrToBinstr("0001"));//Key values are in different card slots
		Element key2 = b.encryptstr(PK, "0020");
		System.out.println("Final_result: " + b.StrToBinstr("0020"));
		Element key3 = b.encryptstr(PK, "0300");
		System.out.println("Final_result: " + b.StrToBinstr("0300"));
		Element key4 = b.encryptstr(PK, "4000");
		System.out.println("Final_result: " + b.StrToBinstr("4000"));

		Element en1 = b.encrypt(PK, 1);//1 means vehicle will pass
		Element en0 = b.encrypt(PK, 0);//0 means the vehicle does not pass

		Element result1 = b.mul(PK, key1, en1);
		Element result2 = b.mul(PK, key2, en1);
		Element result3 = b.mul(PK, key3, en1);
		Element result4 = b.mul(PK, key4, en0);

		Final_result=result1.mul(result2);//
		Final_result=Final_result.mul(result3);//
		Final_result=Final_result.mul(result4);//a secure vector product by BGN
		// Privacy preserving back-propagation neural network learning made practical with cloud computing
		System.out.println("Final_result: " + b.decryptMul(PK, b.q, Final_result));
		System.out.println("Final_result: " + b.StrToBinstr(b.decryptMul(PK, b.q, Final_result)));

		String result[]=new String[4];
		Integer Finalresult[]=new Integer[4];
		result=	b.StrToStrArray(b.StrToBinstr(b.decryptMul(PK, b.q, Final_result)));

		System.out.println(result.length);
		if(result.length<4)
		{
			for(int i=0;i<result.length;i++) {
				Finalresult[i] = Integer.valueOf(result[i], 2) - 48;
				System.out.println("Final_getkey: " + Finalresult[i]);
			}
		}
		for(int i=0;i<4-result.length;i++){
			System.out.println("Final_getkey: " + "0");//Finally get the result
		}
	}
}

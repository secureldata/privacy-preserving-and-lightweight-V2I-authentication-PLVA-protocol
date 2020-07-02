import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1Pairing;
import it.unisa.dia.gas.plaf.jpbc.util.math.BigIntegerUtils;
import org.bouncycastle.jce.provider.JCEMac;
import org.bouncycastle.jce.provider.symmetric.AES;
import javax.swing.*;
import java.lang.Runtime;
public class PLVA_scheme {

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
		// prime																	// numbers.
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
		//System.out.println("Hash is " + m);
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
	public static void main(String[] args) {
		PLVA_scheme b = new PLVA_scheme();
		PublicKey PK = b.gen(256);

		int n=10;//Assume the number of RSU
		int onevalue=0;
		int key[]=new int[n];
		int matrix[][]=new int[n][n];
		double  result[]=new double [n];
		Element Ematrix[][]=new Element[n][n];
		Element Ekey[]=new Element[n];
		Element EC[]=new Element[n];
		Element resultend[]=new Element[n];
		Element one=b.encrypt(PK,1);

		//###############################################################################################

		//###############################################################################################
		for(int i=0;i<n;i++)  //Assuming key vector generation
		{
			key[i]=i+1;
		}
		//###############################################################################################
		//Vehicle pre-calculation
		//###############################################################################################
		for(int i=0;i<n;i++)  //The paths traversed are all set to 1, in order to test the calculation time
		{
			EC[i]=b.encrypt(PK,1);
		}

		//###############################################################################################
		//Calculate cyclic displacement matrix
		//###############################################################################################
		for(int i=0;i<n;i++) {  //Calculate the cyclic displacement matrix where the displacement value is set to 2
			for (int j = 0; j < n; j++) {
				if(j==(i+(n-2))%n)
				{
					matrix[i][j]=1;
				}
				else
				{
					matrix[i][j]=0;
				}
			}
		}
		
		//###############################################################################################
		//Encrypted first line
		//###############################################################################################
		for(int j=0;j<n;j++)  //To encrypt the circular matrix, first encrypt the first row
		{
			Ematrix[0][j] = b.encrypt(PK,matrix[0][j]);
		}
		//###############################################################################################
		//Displacement matrix
		//###############################################################################################
		for(int i=0;i<n-1;i++) { //Number of remaining lines, shifted from the first line
			Element temp=Ematrix[i][n-1];

			for (int j = n-1; j >0; j--) {
				Ematrix[i+1][j]=Ematrix[i][j-1];
			}
			Ematrix[i+1][0]=temp;

		}
		
		//###############################################################################################
		//CA gets the encryption matrix and path vector
		//###############################################################################################

		for(int i=0;i<n;i++) {   //CA receives the encryption matrix and combines the encryption matrix into an encryption vector
			for (int j = 0, s=0; s < n && j<n; j++,s++) {
				Element temp1=Ematrix[i][j];
				for(int k=0;k<key[s];k++){
					temp1=b.add(PK,Ematrix[i][j],temp1);//The exponentiation operation appears as the ADD algorithm in BGN
					Ematrix[i][j]=temp1;
				}
				Ematrix[i][j]=b.add(PK,temp1,b.encrypt(PK,1));
			}

		}
		for(int i=0;i<n;i++) {
			Element temp3=b.encrypt(PK,0);
			for (int j = 0; j<n; j++) {

				temp3=b.add(PK,temp3,Ematrix[i][j]);
			}
			Ekey[i]=temp3;
		}
		for(int i=0;i<n;i++) //Multiply the encrypted vector and the encrypted path vector to the final result vector
		{
			resultend[i]=b.mul(PK,EC[i],Ekey[i]);
		}
		//###############################################################################################
		//Vehicle decryption
		//###############################################################################################
		for(int i=0;i<n;i++)
		{
			result[i]=Double.valueOf(b.decryptMul(PK, b.q, resultend[i]));
			result[i]=result[i]-n;
			System.out.println("result: " + Math.log(result[i])/Math.log(2));
		}

	}
}

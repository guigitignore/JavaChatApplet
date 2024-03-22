package applet;

import javacard.framework.*;
import javacardx.crypto.*;
import javacard.security.*;



public class TheApplet extends Applet {
	//crypto objects
	private Cipher desCipherEncrypt;
	private Cipher desCipherDecrypt;
	private DESKey desKey;
	private static final byte[] desKeyBytes ={ 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0 };

	private KeyPair rsaKeyPair;
	private RSAPublicKey publicRSAKey;
	private RSAPrivateKey privateRSAKey;
	private Cipher rsaCipherDecrypt;
	private final static short RSA_LENGTH=(short)1024;
	private final static short RSA_BYTE_LENGTH=RSA_LENGTH>>3;

	public static final byte DES_ENCRYPT             =0x01;
	public static final byte DES_DECRYPT             =0x02;
	public static final byte RSA_GET_MODULUS         =0x03;
	public static final byte RSA_GET_PUBLIC_EXPONENT =0x04;
	public static final byte RSA_DECRYPT             =0x05;

	private boolean desInit;
	private boolean rsaInit;
	private short keySize;

	protected TheApplet() {
		try{
			desKey= (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
			desKey.setKey(desKeyBytes, (short)0);
			keySize=(short)(desKey.getSize()>>3);

			desCipherEncrypt = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		    desCipherDecrypt = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);

		    desCipherEncrypt.init( desKey, Cipher.MODE_ENCRYPT );
		    desCipherDecrypt.init( desKey, Cipher.MODE_DECRYPT );

			desInit=true;
		}catch(Exception e){
			desInit=false;
		}

		try{
			rsaKeyPair=new KeyPair(KeyPair.ALG_RSA,RSA_LENGTH);
			rsaKeyPair.genKeyPair();
			publicRSAKey=(RSAPublicKey)rsaKeyPair.getPublic();
			privateRSAKey=(RSAPrivateKey)rsaKeyPair.getPrivate();

			rsaCipherDecrypt= Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
			rsaCipherDecrypt.init(privateRSAKey,Cipher.MODE_DECRYPT);

			rsaInit=true;
		}catch(Exception e){
			rsaInit=false;
		}

		this.register();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new TheApplet();
	} 


	public boolean select() {
		return true;
	} 


	public void deselect() {
		
	}


	public void process(APDU apdu) throws ISOException {
		if( selectingApplet() == true )
			return;

		byte[] buffer = apdu.getBuffer();

		//switch commands
		switch( buffer[1] ) 	{
			case DES_ENCRYPT: desEncrypt(apdu); break;
			case DES_DECRYPT: desDecrypt(apdu); break;
			case RSA_GET_MODULUS: rsaGetModulus(apdu); break;
			case RSA_GET_PUBLIC_EXPONENT: rsaGetPublicExponent(apdu); break;
			case RSA_DECRYPT: rsaDecrypt(apdu); break;
			
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}


	private void cipherGeneric( APDU apdu, Cipher cipher) {
		// Write the method ciphering/unciphering data from the computer.
		// The result is sent back to the computer.
		if (desInit==false) ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

        apdu.setIncomingAndReceive();
        byte[] buffer=apdu.getBuffer();
        short length=(short)(buffer[4]&0xFF);

		if (length%keySize!=0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        cipher.doFinal(buffer,(short)5,length,buffer,(short)0);
        apdu.setOutgoingAndSend((short)0,length);
	}

	private void desEncrypt(APDU apdu){
		cipherGeneric(apdu,desCipherEncrypt);
	}

	private void desDecrypt(APDU apdu){
		cipherGeneric(apdu,desCipherDecrypt);
	}

	private void rsaGetModulus(APDU apdu){
		if (rsaInit==false) ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

		short length=publicRSAKey.getModulus(apdu.getBuffer(), (short)0);
		apdu.setOutgoingAndSend((short)0, length);
	}

	private void rsaGetPublicExponent(APDU apdu){
		if (rsaInit==false) ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

		short length=publicRSAKey.getExponent(apdu.getBuffer(), (short)0);
		apdu.setOutgoingAndSend((short)0, length);
	}

	private void rsaDecrypt(APDU apdu){
		if (rsaInit==false) ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

        apdu.setIncomingAndReceive();
        byte[] buffer=apdu.getBuffer();
        short length=(short)(buffer[4]&0xFF);

		if (length>=RSA_BYTE_LENGTH) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		length=rsaCipherDecrypt.doFinal(buffer, (short)0, RSA_BYTE_LENGTH, buffer, (short)0);
		apdu.setOutgoingAndSend((short)0, length);
	}

}

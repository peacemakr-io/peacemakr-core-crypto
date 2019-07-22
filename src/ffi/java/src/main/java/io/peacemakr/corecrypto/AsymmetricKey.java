package io.peacemakr.corecrypto;

public class AsymmetricKey {

	private long nativeKey;

    public static native AsymmetricKey fromPRNG(AsymmetricCipher type, SymmetricCipher symmetricType);
	public static native AsymmetricKey fromPubPem(SymmetricCipher symmetricType, String pubPem);
	public static native AsymmetricKey fromPrivPem(SymmetricCipher symmetricType, String privPem);
	public native String getPubPemStr();
	public native String getPrivPemStr();

	public native byte[] ecdhKeygen(SymmetricCipher symmetricType, AsymmetricKey peerKey);

    // Deallocates asymmetricKeyPtr
	private native void cleanup();

	public void finalize() {
	    cleanup();
	}
}
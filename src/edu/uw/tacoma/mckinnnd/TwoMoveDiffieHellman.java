package edu.uw.tacoma.mckinnnd;

import com.sun.crypto.provider.DHKeyPairGenerator;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.util.Hashtable;

/**
 * Created by Nick McKinney, mckinnnd@uw.edu, on 12/14/16.
 */

public class TwoMoveDiffieHellman {
    private DHPublicKey pubKey;
    private DHPrivateKey privKey;
    private DHParameterSpec dhparams;
    private KeyAgreement keyAgreement;
    private byte[] sessionKey;

    Hashtable<Long, SecurityAssociation> sessionTable;

    /**
     * Constructor method
     */
    public TwoMoveDiffieHellman() {
        sessionTable = new Hashtable<>();
    }

    /**
     * Initializes the object if we're the session initiator (P_i)
     */
    public void init() {
        try {
            GenerateDHParams();
            GenerateKeyPair();
            keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privKey);

            // ComeToAnAgreement();
        } catch(Exception e) {
            System.err.println("Initialization error: " + e.getMessage());
            System.exit(-1);
        }
    }

    /**
     * Initializes the object if we are not the session initiator (P_j)
     * @param key Initiator's public key
     */
    public void init(DHPublicKey key) {
        try {
            dhparams = key.getParams();
            GenerateKeyPair();
            keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privKey);
        } catch(Exception e) {
            System.err.println("Initialization error: " + e.getMessage());
            System.exit(-1);
        }
    }

    public DHPublicKey getPublicKey() { return pubKey; }

    public byte[] getSharedKey() { return keyAgreement.generateSecret(); }

    /**
     * Restores a previous session key into the ephemeral space
     * @param s Session ID
     * @return Byte array representing session key
     */
    public byte[] loadSession(long s) {
        try {
            SecurityAssociation sa = getSession(s);
            sessionKey = sa.getSessionKey();
        } catch (InvalidSessionIDException e) {
            System.err.println(e.getMessage());
        }

        return sessionKey;
    }

    public DHPublicKey clientMessage(TwoMoveDiffieHellman P, long s, boolean initiator) {
        // If we are the initiator
        if (initiator) {
            try {
                // See if the security association already exists
                // If so, load the ephemeral data
                SecurityAssociation sa = getSession(s);
                sessionKey = sa.getSessionKey();
                return null;
            } catch (InvalidSessionIDException e) {
                init();
                DHPublicKey pk = P.clientMessage(this, s, false);
                agreeOnSessionKey(pk);
                sessionTable.put(s, new SecurityAssociation(s, sessionKey, P));
                return pubKey;
            }
        }
        // If the sender is the initiator
        else {
            try {
                SecurityAssociation sa = getSession(s);
                sessionKey = sa.getSessionKey();
                return null;
            } catch (InvalidSessionIDException e) {
                init(P.getPublicKey());
                agreeOnSessionKey(P.getPublicKey());
                sessionTable.put(s, new SecurityAssociation(s, sessionKey, P));
                return pubKey;
            }
        }
    }

    public SecurityAssociation getSession(long s) throws InvalidSessionIDException {
        SecurityAssociation session = sessionTable.get(s);
        if (session == null) { throw new InvalidSessionIDException("No such session: " + s); }

        return session;
    }

    private void GenerateDHParams() throws Exception {
        // Generate DH params here
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        dhparams = params.getParameterSpec(DHParameterSpec.class);
    }

    private void GenerateKeyPair() throws Exception {
        DHKeyPairGenerator dhkpg = new DHKeyPairGenerator();
        dhkpg.initialize(dhparams, new SecureRandom());
        KeyPair kp = dhkpg.generateKeyPair();
        pubKey = (DHPublicKey)kp.getPublic();
        privKey = (DHPrivateKey)kp.getPrivate();
    }

    private void agreeOnSessionKey(DHPublicKey key) {
        try {
            keyAgreement.doPhase(key, true);
        } catch (java.security.InvalidKeyException e) {
            System.err.println("Failure: " + e.getMessage());
            System.exit(-1);
        }
    }
}

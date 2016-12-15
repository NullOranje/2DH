package edu.uw.tacoma.mckinnnd;

/**
 * Created by nicholas on 12/14/16.
 *
 * This is a wrapper class to facilitate indexing previous sessions.
 * @author Nick McKinney
 *
 */

class SecurityAssociation {
    private long sessionID;
    private byte[] gamma;
    private TwoMoveDiffieHellman P;

    /**
     * Constructor
     * @param s Session ID
     * @param sessionKey Byte array representing the agreed upon session key
     * @param P Pointer to other party
     */
    public SecurityAssociation(long s, byte[] sessionKey, TwoMoveDiffieHellman P) {
        sessionID = s;
        gamma = sessionKey;
        this.P = P;
    }

    public long getSessionID() { return sessionID; }

    /**
     * Get method for sessionKey gamma
     * @return Returns agreed upon session key
     */
    public byte[] getSessionKey() { return gamma; }

    public TwoMoveDiffieHellman getPartner() { return P; }
}

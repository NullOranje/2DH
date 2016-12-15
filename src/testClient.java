/**
 * Created by Nick McKinney, mckinnnd@uw.edu, on 12/14/16.
 */

import edu.uw.tacoma.mckinnnd.*;

import java.util.Arrays;
import java.util.Random;

public class testClient {

    public static void main(String[] args) {
	// write your code here
        TwoMoveDiffieHellman alice = new TwoMoveDiffieHellman();
        TwoMoveDiffieHellman bob = new TwoMoveDiffieHellman();
        Random rng = new Random();

        long session = rng.nextLong();

        alice.clientMessage(bob, session, true);
        byte[] aliceKey = alice.getSharedKey();
        byte[] bobKey = bob.getSharedKey();

        System.out.println("Alice:\t" + Arrays.toString(aliceKey));
        System.out.println("Bob:\t" + Arrays.toString(bobKey));

        alice.loadSession(session);
        System.out.println("Alice:\t" + Arrays.toString(aliceKey));

        // This will return an error, since this session doesn't exist
        alice.loadSession(session + 1);

    }
}

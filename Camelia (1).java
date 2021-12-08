

import java.io.File;
import java.nio.file.StandardOpenOption;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.*;
import java.util.Arrays;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;

public class Camelia {

    private static final int MASK8 = 0xff;
    static int[] subkey = new int[24 * 4];
    static int[] kw = new int[4 * 2];
    static int[] ke = new int[6 * 2];
    static int[] state = new int[4];

    static int lengthKey;

    static final int Ci[] = {
            0xa09e667f, 0x3bcc908b,
            0xb67ae858, 0x4caa73b2,
            0xc6ef372f, 0xe94f82be,
            0x54ff53a5, 0xf1d36f1c,
            0x10e527fa, 0xde682d1d,
            0xb05688c2, 0xb3e6c1fd
    };


    static final byte SBOX1[] = {(byte) 112, (byte) 130, (byte) 44, (byte) 236, (byte) 179, (byte) 39, (byte) 192, (byte) 229, (byte) 228, (byte) 133, (byte) 87, (byte) 53,
            (byte) 234, (byte) 12, (byte) 174, (byte) 65, (byte) 35, (byte) 239, (byte) 107, (byte) 147, (byte) 69, (byte) 25, (byte) 165, (byte) 33,
            (byte) 237, (byte) 14, (byte) 79, (byte) 78, (byte) 29, (byte) 101, (byte) 146, (byte) 189, (byte) 134, (byte) 184, (byte) 175, (byte) 143,
            (byte) 124, (byte) 235, (byte) 31, (byte) 206, (byte) 62, (byte) 48, (byte) 220, (byte) 95, (byte) 94, (byte) 197, (byte) 11, (byte) 26,
            (byte) 166, (byte) 225, (byte) 57, (byte) 202, (byte) 213, (byte) 71, (byte) 93, (byte) 61, (byte) 217, (byte) 1, (byte) 90, (byte) 214,
            (byte) 81, (byte) 86, (byte) 108, (byte) 77, (byte) 139, (byte) 13, (byte) 154, (byte) 102, (byte) 251, (byte) 204, (byte) 176, (byte) 45,
            (byte) 116, (byte) 18, (byte) 43, (byte) 32, (byte) 240, (byte) 177, (byte) 132, (byte) 153, (byte) 223, (byte) 76, (byte) 203, (byte) 194,
            (byte) 52, (byte) 126, (byte) 118, (byte) 5, (byte) 109, (byte) 183, (byte) 169, (byte) 49, (byte) 209, (byte) 23, (byte) 4, (byte) 215,
            (byte) 20, (byte) 88, (byte) 58, (byte) 97, (byte) 222, (byte) 27, (byte) 17, (byte) 28, (byte) 50, (byte) 15, (byte) 156, (byte) 22,
            (byte) 83, (byte) 24, (byte) 242, (byte) 34, (byte) 254, (byte) 68, (byte) 207, (byte) 178, (byte) 195, (byte) 181, (byte) 122, (byte) 145,
            (byte) 36, (byte) 8, (byte) 232, (byte) 168, (byte) 96, (byte) 252, (byte) 105, (byte) 80, (byte) 170, (byte) 208, (byte) 160, (byte) 125,
            (byte) 161, (byte) 137, (byte) 98, (byte) 151, (byte) 84, (byte) 91, (byte) 30, (byte) 149, (byte) 224, (byte) 255, (byte) 100, (byte) 210,
            (byte) 16, (byte) 196, (byte) 0, (byte) 72, (byte) 163, (byte) 247, (byte) 117, (byte) 219, (byte) 138, (byte) 3, (byte) 230, (byte) 218,
            (byte) 9, (byte) 63, (byte) 221, (byte) 148, (byte) 135, (byte) 92, (byte) 131, (byte) 2, (byte) 205, (byte) 74, (byte) 144, (byte) 51,
            (byte) 115, (byte) 103, (byte) 246, (byte) 243, (byte) 157, (byte) 127, (byte) 191, (byte) 226, (byte) 82, (byte) 155, (byte) 216, (byte) 38,
            (byte) 200, (byte) 55, (byte) 198, (byte) 59, (byte) 129, (byte) 150, (byte) 111, (byte) 75, (byte) 19, (byte) 190, (byte) 99, (byte) 46,
            (byte) 233, (byte) 121, (byte) 167, (byte) 140, (byte) 159, (byte) 110, (byte) 188, (byte) 142, (byte) 41, (byte) 245, (byte) 249, (byte) 182,
            (byte) 47, (byte) 253, (byte) 180, (byte) 89, (byte) 120, (byte) 152, (byte) 6, (byte) 106, (byte) 231, (byte) 70, (byte) 113, (byte) 186,
            (byte) 212, (byte) 37, (byte) 171, (byte) 66, (byte) 136, (byte) 162, (byte) 141, (byte) 250, (byte) 114, (byte) 7, (byte) 185, (byte) 85,
            (byte) 248, (byte) 238, (byte) 172, (byte) 10, (byte) 54, (byte) 73, (byte) 42, (byte) 104, (byte) 60, (byte) 56, (byte) 241, (byte) 164,
            (byte) 64, (byte) 40, (byte) 211, (byte) 123, (byte) 187, (byte) 201, (byte) 67, (byte) 193, (byte) 21, (byte) 227, (byte) 173, (byte) 244,
            (byte) 119, (byte) 199, (byte) 128, (byte) 158
    };

    static final int rightRotate(int x, int s) {

        return (((x) >>> (s)) + ((x) << (32 - s)));
    }

    ;

    static final int leftRotate(int x, int s) {
        return ((x) << (s)) + ((x) >>> (32 - s));
    }

    ;

    static final void Rol(int rot, int[] ki, int ioff, int[] ko, int ooff) {
        ko[0 + ooff] = (ki[0 + ioff] << rot) | (ki[1 + ioff] >>> (32 - rot));
        ko[1 + ooff] = (ki[1 + ioff] << rot) | (ki[2 + ioff] >>> (32 - rot));
        ko[2 + ooff] = (ki[2 + ioff] << rot) | (ki[3 + ioff] >>> (32 - rot));
        ko[3 + ooff] = (ki[3 + ioff] << rot) | (ki[0 + ioff] >>> (32 - rot));
        ki[0 + ioff] = ko[0 + ooff];
        ki[1 + ioff] = ko[1 + ooff];
        ki[2 + ioff] = ko[2 + ooff];
        ki[3 + ioff] = ko[3 + ooff];
    }

    static final void decRol(int rot, int[] ki, int ioff, int[] ko, int ooff) {
        ko[2 + ooff] = (ki[0 + ioff] << rot) | (ki[1 + ioff] >>> (32 - rot));
        ko[3 + ooff] = (ki[1 + ioff] << rot) | (ki[2 + ioff] >>> (32 - rot));
        ko[0 + ooff] = (ki[2 + ioff] << rot) | (ki[3 + ioff] >>> (32 - rot));
        ko[1 + ooff] = (ki[3 + ioff] << rot) | (ki[0 + ioff] >>> (32 - rot));
        ki[0 + ioff] = ko[2 + ooff];
        ki[1 + ioff] = ko[3 + ooff];
        ki[2 + ioff] = ko[0 + ooff];
        ki[3 + ioff] = ko[1 + ooff];
    }

    static final void rol32(int rot, int[] ki, int ioff, int[] ko, int ooff) {
        ko[0 + ooff] = (ki[1 + ioff] << (rot - 32)) | (ki[2 + ioff] >>> (64 - rot));
        ko[1 + ooff] = (ki[2 + ioff] << (rot - 32)) | (ki[3 + ioff] >>> (64 - rot));
        ko[2 + ooff] = (ki[3 + ioff] << (rot - 32)) | (ki[0 + ioff] >>> (64 - rot));
        ko[3 + ooff] = (ki[0 + ioff] << (rot - 32)) | (ki[1 + ioff] >>> (64 - rot));
        ki[0 + ioff] = ko[0 + ooff];
        ki[1 + ioff] = ko[1 + ooff];
        ki[2 + ioff] = ko[2 + ooff];
        ki[3 + ioff] = ko[3 + ooff];
    }

    static final void decRol32(int rot, int[] ki, int ioff, int[] ko, int ooff) {
        ko[2 + ooff] = (ki[1 + ioff] << (rot - 32)) | (ki[2 + ioff] >>> (64 - rot));
        ko[3 + ooff] = (ki[2 + ioff] << (rot - 32)) | (ki[3 + ioff] >>> (64 - rot));
        ko[0 + ooff] = (ki[3 + ioff] << (rot - 32)) | (ki[0 + ioff] >>> (64 - rot));
        ko[1 + ooff] = (ki[0 + ioff] << (rot - 32)) | (ki[1 + ioff] >>> (64 - rot));
        ki[0 + ioff] = ko[2 + ooff];
        ki[1 + ioff] = ko[3 + ooff];
        ki[2 + ioff] = ko[0 + ooff];
        ki[3 + ioff] = ko[1 + ooff];
    }

    static void keyLen(int len) {
        switch (len) {
            case 128:
                lengthKey = 16;
                break;
            case 192:
                lengthKey = 24;
                break;
            case 256:
                lengthKey = 32;
                break;
        }
    }

    static final byte leftRotate8(byte v, int rot) {
        return (byte) ((v << rot) | ((v & 0xff) >>> (8 - rot)));
    }

    static final int SBOX2(int x) {
        return (leftRotate8(SBOX1[x], 1) & MASK8);
    }

    static final int SBOX3(int x) {
        return (leftRotate8(SBOX1[x], 7) & MASK8);
    }

    static final int SBOX4(int x) {
        return (SBOX1[((int) leftRotate8((byte) x, 1) & MASK8)] & MASK8);
    }

    static final void F(int[] s, int[] skey, int keyoff) {
        int t1, t2, u, v;

        t1 = s[0] ^ skey[0 + keyoff];
        u = SBOX4((t1 & MASK8));
        u |= (SBOX3(((t1 >>> 8) & MASK8)) << 8);
        u |= (SBOX2(((t1 >>> 16) & MASK8)) << 16);
        u |= ((SBOX1[((t1 >>> 24) & MASK8)] & MASK8) << 24);

        t2 = s[1] ^ skey[1 + keyoff];
        v = (int) SBOX1[(t2 & MASK8)] & MASK8;
        v |= (SBOX4(((t2 >>> 8) & MASK8)) << 8);
        v |= (SBOX3(((t2 >>> 16) & MASK8)) << 16);
        v |= (SBOX2(((t2 >>> 24) & MASK8)) << 24);

        v = leftRotate(v, 8);
        u ^= v;
        v = leftRotate(v, 8) ^ u;
        u = rightRotate(u, 8) ^ v;
        s[2] ^= leftRotate(v, 16) ^ u;
        s[3] ^= leftRotate(u, 8);
        ;

        t1 = s[2] ^ skey[2 + keyoff];
        u = SBOX4((t1 & MASK8));
        u |= SBOX3(((t1 >>> 8) & MASK8)) << 8;
        u |= SBOX2(((t1 >>> 16) & MASK8)) << 16;
        u |= ((int) SBOX1[((t1 >>> 24) & MASK8)] & MASK8) << 24;

        t2 = s[3] ^ skey[3 + keyoff];
        v = ((int) SBOX1[(t2 & MASK8)] & MASK8);
        v |= SBOX4(((t2 >>> 8) & MASK8)) << 8;
        v |= SBOX3(((t2 >>> 16) & MASK8)) << 16;
        v |= SBOX2(((t2 >>> 24) & MASK8)) << 24;

        v = leftRotate(v, 8);
        u ^= v;
        v = leftRotate(v, 8) ^ u;
        u = rightRotate(u, 8) ^ v;
        s[0] ^= leftRotate(v, 16) ^ u;
        s[1] ^= leftRotate(u, 8);
    }

    static final void FL(int[] s, int[] fkey, int keyoff) {

        s[1] ^= leftRotate(s[0] & fkey[0 + keyoff], 1);
        s[0] ^= fkey[1 + keyoff] | s[1];

        s[2] ^= fkey[3 + keyoff] | s[3];
        s[3] ^= leftRotate(fkey[2 + keyoff] & s[2], 1);
    }

    static final void keyGeneration(boolean Enc, byte[] key) {
        int[] k = new int[8];
        int[] ka = new int[4];
        int[] kb = new int[4];
        int[] t = new int[4];

        switch (Camelia.lengthKey) {
            case 16:
                k[0] = bytesToint(key, 0);
                k[1] = bytesToint(key, 4);
                k[2] = bytesToint(key, 8);
                k[3] = bytesToint(key, 12);
                k[4] = k[5] = k[6] = k[7] = 0;
                break;
            case 24:
                k[0] = bytesToint(key, 0);
                k[1] = bytesToint(key, 4);
                k[2] = bytesToint(key, 8);
                k[3] = bytesToint(key, 12);
                k[4] = bytesToint(key, 16);
                k[5] = bytesToint(key, 20);
                k[6] = ~k[4];
                k[7] = ~k[5];
                break;
            case 32:
                k[0] = bytesToint(key, 0);
                k[1] = bytesToint(key, 4);
                k[2] = bytesToint(key, 8);
                k[3] = bytesToint(key, 12);
                k[4] = bytesToint(key, 16);
                k[5] = bytesToint(key, 20);
                k[6] = bytesToint(key, 24);
                k[7] = bytesToint(key, 28);
                break;

        }

        for (int i = 0; i < 4; i++) {
            ka[i] = k[i] ^ k[i + 4];
        }

        F(ka, Ci, 0);
        for (int i = 0; i < 4; i++) {
            ka[i] ^= k[i];
        }
        F(ka, Ci, 4);

        if (Camelia.lengthKey == 16) {
            if (Enc) {
                kw[0] = k[0];
                kw[1] = k[1];
                kw[2] = k[2];
                kw[3] = k[3];
                Rol(15, k, 0, subkey, 4);
                Rol(30, k, 0, subkey, 12);
                Rol(15, k, 0, t, 0);
                subkey[18] = t[2];
                subkey[19] = t[3];
                Rol(17, k, 0, ke, 4);
                Rol(17, k, 0, subkey, 24);
                Rol(17, k, 0, subkey, 32);

                subkey[0] = ka[0];
                subkey[1] = ka[1];
                subkey[2] = ka[2];
                subkey[3] = ka[3];
                Rol(15, ka, 0, subkey, 8);
                Rol(15, ka, 0, ke, 0);
                Rol(15, ka, 0, t, 0);
                subkey[16] = t[0];
                subkey[17] = t[1];
                Rol(15, ka, 0, subkey, 20);
                rol32(34, ka, 0, subkey, 28);
                Rol(17, ka, 0, kw, 4);

            } else {

                kw[4] = k[0];
                kw[5] = k[1];
                kw[6] = k[2];
                kw[7] = k[3];
                decRol(15, k, 0, subkey, 28);
                decRol(30, k, 0, subkey, 20);
                decRol(15, k, 0, t, 0);
                subkey[16] = t[0];
                subkey[17] = t[1];
                decRol(17, k, 0, ke, 0);
                decRol(17, k, 0, subkey, 8);
                decRol(17, k, 0, subkey, 0);

                subkey[34] = ka[0];
                subkey[35] = ka[1];
                subkey[32] = ka[2];
                subkey[33] = ka[3];
                decRol(15, ka, 0, subkey, 24);
                decRol(15, ka, 0, ke, 4);
                decRol(15, ka, 0, t, 0);
                subkey[18] = t[2];
                subkey[19] = t[3];
                decRol(15, ka, 0, subkey, 12);
                decRol32(34, ka, 0, subkey, 4);
                Rol(17, ka, 0, kw, 0);
            }
        } else {

            for (int i = 0; i < 4; i++) {
                kb[i] = ka[i] ^ k[i + 4];
            }
            F(kb, Ci, 8);

            if (Enc) {

                kw[0] = k[0];
                kw[1] = k[1];
                kw[2] = k[2];
                kw[3] = k[3];
                rol32(45, k, 0, subkey, 16);
                Rol(15, k, 0, ke, 4);
                Rol(17, k, 0, subkey, 32);
                rol32(34, k, 0, subkey, 44);

                Rol(15, k, 4, subkey, 4);
                Rol(15, k, 4, ke, 0);
                Rol(30, k, 4, subkey, 24);
                rol32(34, k, 4, subkey, 36);

                Rol(15, ka, 0, subkey, 8);
                Rol(30, ka, 0, subkey, 20);

                ke[8] = ka[1];
                ke[9] = ka[2];
                ke[10] = ka[3];
                ke[11] = ka[0];
                rol32(49, ka, 0, subkey, 40);


                subkey[0] = kb[0];
                subkey[1] = kb[1];
                subkey[2] = kb[2];
                subkey[3] = kb[3];
                Rol(30, kb, 0, subkey, 12);
                Rol(30, kb, 0, subkey, 28);
                rol32(51, kb, 0, kw, 4);

            } else {

                kw[4] = k[0];
                kw[5] = k[1];
                kw[6] = k[2];
                kw[7] = k[3];
                decRol32(45, k, 0, subkey, 28);
                decRol(15, k, 0, ke, 4);
                decRol(17, k, 0, subkey, 12);
                decRol32(34, k, 0, subkey, 0);

                decRol(15, k, 4, subkey, 40);
                decRol(15, k, 4, ke, 8);
                decRol(30, k, 4, subkey, 20);
                decRol32(34, k, 4, subkey, 8);

                decRol(15, ka, 0, subkey, 36);
                decRol(30, ka, 0, subkey, 24);

                ke[2] = ka[1];
                ke[3] = ka[2];
                ke[0] = ka[3];
                ke[1] = ka[0];
                decRol32(49, ka, 0, subkey, 4);


                subkey[46] = kb[0];
                subkey[47] = kb[1];
                subkey[44] = kb[2];
                subkey[45] = kb[3];
                decRol(30, kb, 0, subkey, 32);
                decRol(30, kb, 0, subkey, 16);
                rol32(51, kb, 0, kw, 0);
            }
        }
    }

    static private byte[] XOR(byte[] blockOne, byte[] blockTwo) {
        byte[] outBlock = new byte[16];
        for (int i = 0; i < 16; i++)
            outBlock[i] = (byte) (blockOne[i] ^ blockTwo[i]);
        return outBlock;
    }

    static final int bytesToint(byte[] src, int offset) {
        int word = 0;

        for (int i = 0; i < 4; i++) {
            word = (word << 8) + (src[i + offset] & MASK8);
        }
        return word;
    }

    static final void intTobytes(int word, byte[] dst, int offset) {
        for (int i = 0; i < 4; i++) {
            dst[(3 - i) + offset] = (byte) word;
            word >>>= 8;
        }
    }

    static byte[] EncryptBlock(byte[] block) {
        byte[] out_block = new byte[16];
        for (int i = 0; i < 4; i++) {
            state[i] = bytesToint(block, i * 4);
            state[i] ^= kw[i];
        }
        if (lengthKey == 16) {
            F(state, subkey, 0);
            F(state, subkey, 4);
            F(state, subkey, 8);
            FL(state, ke, 0);
            F(state, subkey, 12);
            F(state, subkey, 16);
            F(state, subkey, 20);
            FL(state, ke, 4);
            F(state, subkey, 24);
            F(state, subkey, 28);
            F(state, subkey, 32);

            state[2] ^= kw[4];
            state[3] ^= kw[5];
            state[0] ^= kw[6];
            state[1] ^= kw[7];

            intTobytes(state[2], out_block, 0);
            intTobytes(state[3], out_block, 4);
            intTobytes(state[0], out_block, 8);
            intTobytes(state[1], out_block, 12);
            return out_block;
        } else {
            F(state, subkey, 0);
            F(state, subkey, 4);
            F(state, subkey, 8);
            FL(state, ke, 0);
            F(state, subkey, 12);
            F(state, subkey, 16);
            F(state, subkey, 20);
            FL(state, ke, 4);
            F(state, subkey, 24);
            F(state, subkey, 28);
            F(state, subkey, 32);
            FL(state, ke, 8);
            F(state, subkey, 36);
            F(state, subkey, 40);
            F(state, subkey, 44);

            state[2] ^= kw[4];
            state[3] ^= kw[5];
            state[0] ^= kw[6];
            state[1] ^= kw[7];

            intTobytes(state[2], out_block, 0);
            intTobytes(state[3], out_block, 4);
            intTobytes(state[0], out_block, 8);
            intTobytes(state[1], out_block, 12);
        }
        return out_block;
    }

    static void EncryptAndWriteRead(String Plaintext, String EncText, byte[] key, byte[] IV) {
        keyGeneration(true, key);
        File P = new File(Plaintext);
        byte[] text = new byte[1];
        byte[] block;
        byte[] iv = IV;
        try {
            text = Files.readAllBytes(Paths.get(Plaintext));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        int lastBytes = text.length % 16;
        byte[] newText = new byte[text.length + (16 - lastBytes)];

        for (int i = 0; i < text.length; i += 16) {
            block = Arrays.copyOfRange(text, i, i + 16);
            iv = EncryptModeCFB(block, iv);
            System.arraycopy(block, 0, newText, i, 16);
        }
        try {
            Files.write(Paths.get(EncText), newText, StandardOpenOption.APPEND, StandardOpenOption.CREATE);
        } catch (IOException e) {
            e.printStackTrace();
        }
        P.delete();
    }

    static void DecryptAndWRiteRead(String Plaintext, String EncText, byte[] key, byte[] IV) {
        keyGeneration(true, key);
        File P = new File("iv" + EncText + ".txt");
        File E = new File(EncText);
        byte[] text = new byte[1];
        byte[] block;
        byte[] iv = IV;
        byte[] t;
        try {
            text = Files.readAllBytes(Paths.get(EncText));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        int lastBytes = text.length % 16;
        byte[] newText = new byte[text.length + (16 - lastBytes)];

        for (int i = 0; i < text.length; i += 16) {
            block = Arrays.copyOfRange(text, i, i + 16);
            t = block;
            DecryptModeCFB(block, iv);
            System.arraycopy(block, 0, newText, i, 16);
            iv = t;
        }
        try {
            Files.write(Paths.get(Plaintext), newText, StandardOpenOption.APPEND, StandardOpenOption.CREATE);
        } catch (IOException e) {
            e.printStackTrace();
        }

        P.delete();
        E.delete();
    }

    static public byte[] EncryptModeCFB(byte[] block, byte[] iv){
      block = XOR(block, EncryptBlock(iv));
    return block;
    }

    static public byte[] DecryptModeCFB(byte[] block, byte[] iv){
      block = XOR(block, EncryptBlock(iv));
    return block;
    }

    static byte[] PassToKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] a = key.getBytes();
        KeySpec spec = new PBEKeySpec(key.toCharArray(), a, 100, Camelia.lengthKey * 8);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return f.generateSecret(spec).getEncoded();
    }

    public static byte[] InitializationVector() {
        SecureRandom r = new SecureRandom();
        byte[] IV = new byte[16];
        r.nextBytes(IV);
        return IV;
    }

    static void writeInitializationVector(byte[] iv, String str) {
        try {
            Files.write(Paths.get("iv" + str + ".txt"), iv, StandardOpenOption.APPEND, StandardOpenOption.CREATE);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static byte[] readInitializationVector(String str) {
        byte[] iv = new byte[16];
        try {
            iv = Files.readAllBytes(Paths.get("iv" + str + ".txt"));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return iv;
    }

}

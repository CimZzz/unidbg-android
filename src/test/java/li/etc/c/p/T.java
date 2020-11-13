package li.etc.c.p;


import java.util.Base64;

public class T {

    public interface a {
        void a(String str);
    }

    public static native byte[] d(byte[] bArr);

    public static native byte[] e(byte[] bArr);

    public static native byte[] mc(boolean z, byte[] bArr);

    public static native byte[] zas();

    public static void a(a aVar) {
        String str = "cpt";
        if (aVar != null) {
            aVar.a(str);
        } else {
            System.loadLibrary(str);
        }
    }

    public static String a(byte[] bArr) {
        if (bArr == null || bArr.length == 0) {
            return null;
        }
        return Base64.getEncoder().withoutPadding().encodeToString(bArr);
    }

    public static byte[] a(String str) {
        return Base64.getDecoder().decode(str);
    }
}

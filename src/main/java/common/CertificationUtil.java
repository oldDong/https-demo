package common;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

/**
 * 证书操作类
 *
 * User: dongzj
 * Mail: dongzj@shinemo.com
 * Date: 2018/7/3
 * Time: 14:43
 */
public class CertificationUtil {

    /**
     * 读取证书信息
     *
     * @return
     * @throws Exception
     */
    public static byte[] readCertifications() throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        InputStream in = new FileInputStream("/Users/dongzj/Workspaces/test/httpsDemo/https.crt");
        Certificate cate = factory.generateCertificate(in);
        return cate.getEncoded();
    }

    /**
     * 读取私钥信息
     *
     * @return
     * @throws Exception
     */
    public static byte[] readPrivateKey() throws Exception {
        KeyStore store = KeyStore.getInstance("JKS");
        InputStream in = new FileInputStream("/Users/dongzj/Workspaces/test/httpsDemo/https.keystore");
        store.load(in, "dongzj".toCharArray());
        PrivateKey pk = (PrivateKey) store.getKey("dongzj", "dongzj".toCharArray());
        return pk.getEncoded();
    }

    /**
     * 读取公钥信息
     *
     * @return
     * @throws Exception
     */
    public static PublicKey readPublicKey() throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        InputStream in = new FileInputStream("/Users/dongzj/Workspaces/test/httpsDemo/https.crt");
        Certificate cate = factory.generateCertificate(in);
        return cate.getPublicKey();
    }

    /**
     * 证书生成
     *
     * @param b
     * @return
     * @throws Exception
     */
    public static Certificate createCertifate(byte[] b) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(b);
        Certificate cate = factory.generateCertificate(in);
        return cate;
    }

    /**
     * 二进制转十六进制
     *
     * @param b
     * @return
     */
    public static String byte2hex(byte[] b) {
        String hs = "";
        String tmp = "";
        for (int i = 0; i < b.length; i++) {
            tmp = (Integer.toHexString(b[i] & 0XFF));
            if (tmp.length() == 1) {
                hs = hs + "0" + tmp;
            } else {
                hs = hs + tmp;
            }
        }
        return hs.toUpperCase();
    }
}

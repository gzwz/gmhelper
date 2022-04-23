package org.zz.gmhelper;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.zz.gmhelper.test.GMBaseTest;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class Demo {

    static BCECPrivateKey priKey = null;
    static BCECPublicKey pubKey = null;

    public static void main(String[] args) {
//        generateKey();
        sign();
    }
    static {
        try {
            System.out.println("--------------------------生成密钥------------------------");
            KeyPair keyPair1 = SM2Util.generateKeyPair();
            BCECPublicKey aPublic = (BCECPublicKey)keyPair1.getPublic();
            BCECPrivateKey aPrivate =(BCECPrivateKey) keyPair1.getPrivate();
            priKey = aPrivate;
            pubKey = aPublic;
            String puk  = Hex.toHexString(aPublic.getQ().getEncoded(false));
            String pukc =  Hex.toHexString(aPublic.getQ().getEncoded(true));
            String prk  = Hex.toHexString(aPrivate.getD().toByteArray());
            System.out.println("生成未压缩公钥："+puk);
            System.out.println("生成压缩公钥："+pukc);
            System.out.println("生成私钥："+prk);
            System.out.println("--------------------------生成密钥------------------------");

        } catch ( Exception e) {
            e.printStackTrace();
        }
    }
    private static void sign() {
        String signSrc = "aabbcc";
        byte[] sign = null;
        try {
            System.out.println("-------------------------签名验签-------------------------");
            sign = SM2Util.sign(priKey, signSrc.getBytes(StandardCharsets.UTF_8));
            String signRet = Hex.toHexString(sign);
            System.out.println("签名数据："+signRet);

            boolean verify = SM2Util.verify(pubKey, signSrc.getBytes(StandardCharsets.UTF_8), sign);
            System.out.println("验签结果："+verify);
            System.out.println("-------------------------签名验签-------------------------");

        } catch (CryptoException e) {
            e.printStackTrace();
        }
    }


    private static void generateKey() {


        AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
        ECPrivateKeyParameters priKeyParams = (ECPrivateKeyParameters) keyPair.getPrivate();

        ECPublicKeyParameters pubKeyParams = (ECPublicKeyParameters) keyPair.getPublic();

        byte[] pkcs8Bytes = BCECUtil.convertECPrivateKeyToPKCS8(priKeyParams, pubKeyParams);

        BCECPrivateKey priKey = null;
        try {
            priKey = BCECUtil.convertPKCS8ToECPrivateKey(pkcs8Bytes);
            byte[] sign = SM2Util.sign(priKey, GMBaseTest.WITH_ID, GMBaseTest.SRC_DATA);
            System.out.println("SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));
            boolean flag = SM2Util.verify(pubKeyParams, GMBaseTest.WITH_ID, GMBaseTest.SRC_DATA, sign);
            if (!flag) {
                Assert.fail("[withId] verify failed");
            }
        } catch ( Exception e) {
            e.printStackTrace();
        }


    }
}

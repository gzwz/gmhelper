package org.zz.gmhelper;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Test {
    public static void main(String[] args) {
        KeyPair keyPair1 = null;
        try {
            keyPair1 = SM2Util.generateKeyPair();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        BCECPublicKey aPublic = (BCECPublicKey)keyPair1.getPublic();
        BCECPrivateKey aPrivate =(BCECPrivateKey) keyPair1.getPrivate();
        String puk  = Hex.toHexString(aPublic.getQ().getEncoded(false));
        String pukc =  Hex.toHexString(aPublic.getQ().getEncoded(true));
        String prk  = Hex.toHexString(aPrivate.getD().toByteArray());
        System.out.println("生成未压缩公钥："+puk);
        System.out.println("生成压缩公钥："+pukc);
        System.out.println("生成私钥："+prk);
        System.out.println("--------------------------生成密钥------------------------");
        byte pk[] =  aPublic.getQ().getEncoded(false);
        byte pkc[] =  aPublic.getQ().getEncoded(true);
        System.out.println(pk.length);
        String bsr = Base64.toBase64String(pk);
        System.out.println(bsr);
        System.out.println(bsr.length());
        System.out.println("0-00-----------------");
        String bsr1 = Base64.toBase64String(pkc);
        System.out.println(bsr1);
        System.out.println(bsr1.length());

        System.out.println("------------------------1111111---------------------------");
        String srcPuk = "042CC10C63BB131760A953F93BC9D6C728CC52F683A5CB993DF5190C924DDC320B1EA85ABFE7E7D0AE9554302FC77D40985B009C777712459E1520B2DBFC22D116";
        byte[] decode = Hex.decode(srcPuk);
        String s = Base64.toBase64String(decode);
        System.out.println(s);
        System.out.println("------------------------2222222---------------------------");
               srcPuk = "2CC10C63BB131760A953F93BC9D6C728CC52F683A5CB993DF5190C924DDC320B1EA85ABFE7E7D0AE9554302FC77D40985B009C777712459E1520B2DBFC22D116";
        decode = Hex.decode(srcPuk);
        s = Base64.toBase64String(decode);
        System.out.println(s);

        System.out.println("-----------------------333333-----------------------------------");
        byte[] decode1 = Base64.decode("BOR96LfWnHCkGX/vXmNhk9+M198W/bjl/T9Lwih7Q+n/QlNYimlS3fSGeoDFHCLIQKvA9LzFy47TGTS99L/JB6Q=");
        System.out.println(Hex.toHexString(decode1));

    }
}

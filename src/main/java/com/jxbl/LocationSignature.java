package com.jxbl;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.List;

public class LocationSignature {
    public void sign(File pdfFile,
                     InputStream p12stream,
                     char[] password,
                     InputStream src,
                     OutputStream dest,
                     String reason,
                     String location,
                     String chapterPath) throws GeneralSecurityException, IOException, DocumentException {
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
        //读取keystone，获得私钥和证书链
        pkcs12.load(p12stream, password);
        String alias = pkcs12.aliases().nextElement();
        PrivateKey key = (PrivateKey) pkcs12.getKey(alias, password);
        Certificate[] chain = pkcs12.getCertificateChain(alias);

        //下边的步骤都是固定的，照着写就行了，没啥要解释的
        // Creating the reader and the stamper，开始pdfreader
        PdfReader reader = new PdfReader(src);

        //目标文件输出流
        //创建签章工具PdfStamper ，最后一个boolean参数
        //false的话，pdf文件只允许被签名一次，多次签名，最后一次有效
        //true的话，pdf可以被追加签名，验签工具可以识别出每次签名之后文档是否被修改
        PdfStamper stamper = PdfStamper.createSignature(reader, dest, '\0', null, false);
        // 获取数字签章属性对象，设定数字签章的属性
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);

        //添加：查找关键字位置
        byte[] pdfData = new byte[(int) pdfFile.length()];
        try (FileInputStream inputStream = new FileInputStream(pdfFile)) {
            inputStream.read(pdfData);
        } catch (IOException e) {
            throw e;
        }
        List<float[]> position = PdfUtils.findKeywordPostions(pdfData, "（公章）");

        //设置签名的位置，页码，签名域名称，多次追加签名的时候，签名域名称不能一样
        //签名的位置，是图章相对于pdf页面的位置坐标，原点为pdf页面左下角
        //四个参数的分别是，图章左下角x，图章左下角y，图章右上角x，图章右上角y
        appearance.setVisibleSignature(new Rectangle(position.get(0)[1]-20, position.get(0)[2]+50, position.get(0)[1] + 80, position.get(0)[2] - 50), (int) position.get(0)[0], "jxblSign");

        //读取图章图片，这个image是itext包的image
        Image image = Image.getInstance(chapterPath);
        appearance.setSignatureGraphic(image);
        appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
        //设置图章的显示方式，如下选择的是只显示图章（还有其他的模式，可以图章和签名描述一同显示）
        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

        // 这里的itext提供了2个用于签名的接口，可以自己实现，后边着重说这个实现
        // 摘要算法
        BouncyCastleDigest digest = new BouncyCastleDigest();
        // 签名算法
        PrivateKeySignature signature = new PrivateKeySignature(key, DigestAlgorithms.SHA1, null);
        // 调用itext签名方法完成pdf签章CryptoStandard.CMS 签名方式，建议采用这种
        MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
    }

    public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException {
        LocationSignature locationSignature = new LocationSignature();
        String KEYSTORE = "D:\\jxbl.p12";
        char[] PASSWORD = "123456".toCharArray();
        String SRC = "D:\\letterToSign.pdf";
        String DEST = "D:\\letterSinged.pdf";
        String chapterPath = "D:\\stamp.png";
        String reason = "江西省公共资源交易集团专用电子保函签章";
        String location = "江西南昌";

        locationSignature.sign(new File(SRC), new FileInputStream(KEYSTORE), PASSWORD, new FileInputStream(SRC), new FileOutputStream(DEST), reason, location, chapterPath);
        System.out.println("签章完成");
    }
}
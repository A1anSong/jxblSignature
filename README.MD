java version "11.0.18"

keytool -genkeypair -alias jxblkey -keypass 123456 -storepass 123456 -dname "C=中国 S=江西 L=上饶 O=玉山县玉清融资担保有限责任公司 OU=玉山县玉清融资担保有限责任公司 CN=玉山县玉清融资担保有限责任公司" -keyalg RSA -keysize 2048 -validity 3650 -storetype pkcs12 -keystore jxbl.p12

java -jar  jxblSignature-jar-with-dependencies.jar 签名问及教案 源文件路径 目标文件露脊鲸 公章路径 法人章路径
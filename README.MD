java version "11.0.17" 2022-10-18 LT

keytool -genkeypair -alias jxblkey -keypass 123456 -storepass 123456 -dname "C=中国 S=江西 L=上饶 O=玉山县玉清融资担保有限责任公司 OU=玉山县玉清融资担保有限责任公司 CN=玉山县玉清融资担保有限责任公司" -keyalg RSA -keysize 2048 -validity 3650 -storetype pkcs12 -keystore jxbl.p12
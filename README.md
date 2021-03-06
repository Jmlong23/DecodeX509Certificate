---
title: x.509数字证书的解析
toc: true
date: 2020-09-24 11:40:34
tags:
categories: c++密码学

---

# 要求

X509规格的证书，要求解析出他的
 1、序列号
 2、签名算法
 3、使用者
 4、公钥
 5、有效期开始，有效期结束 时间

<!--more-->

# 什么是x.509数字证书

<https://blog.csdn.net/xy010902100449/article/details/52145009>

## 数字证书：

数字证书就是互联网通讯中标志通讯各方身份信息的一系列数据，提供了一种在Internet上验证您身份的方式，其作用类似于司机的驾驶执照或日常生活中的身份证。它是由一个由权威机构—–CA机构，又称为证书授权，（Certificate Authority）中心发行的，人们可以在网上用它来识别对方的身份。数字证书是一个经证书授权中心数字签名的包含公开密钥拥有者信息以及公开密钥的文件。最简单的证书包含一个公开密钥、名称以及证书授权中心的数字签名。

## 什么叫X.509数字证书

X.509 标准规定了证书可以包含什么信息，并说明了记录信息的方法（数据格式）。除了签名外，所有 X.509 证书还包含以下数据：

```
**版本**
识别用于该证书的 X.509 标准的版本，这可以影响证书中所能指定的信息。迄今为止，已定义的版本有三个。
**序列号**
发放证书的实体有责任为证书指定序列号，以使其区别于该实体发放的其它证书。此信息用途很多。例如，如果某一证书被撤消，其序列号将放到证书撤消清单 (CRL) 中。
**签名算法标识符**
用于识别 CA 签写证书时所用的算法。
**签发人姓名**
签写证书的实体的 X.500 名称。它通常为一个 CA。 使用该证书意味着信任签写该证书的实体（注意：有些情况下（例如根或顶层 CA 证书），签发人会签写自己的证书）。
**有效期**
每个证书均只能在一个有限的时间段内有效。该有效期以起始日期和时间及终止日期和时间表示，可以短至几秒或长至一世纪。所选有效期取决于许多因素，例如用于签写证书的私钥的使用频率及愿为证书支付的金钱等。它是在没有危及相关私钥的条件下，实体可以依赖公钥值的预计时间。
**主体名**
证书可以识别其公钥的实体名。此名称使用 X.500 标准，因此在Internet中应是唯一的。它是实体的特征名 (DN)，例如，
CN=Java Duke，OU=Java Software Division，O=Sun Microsystems Inc，C=US
（这些指主体的通用名、组织单位、组织和国家）。
**主体公钥信息**
这是被命名实体的公钥，同时包括指定该密钥所属公钥密码系统的算法标识符及所有相关的密钥参数。
```

## x509数字证书的数据结构和存储结构

https://www.cnblogs.com/chnking/archive/2007/08/28/872104.html

# x.509数据证书的解码

## 法一：用openssl解析

证书格式是Base64的

<https://blog.csdn.net/liumiaocn/article/details/103483123>

```
解析命令
-in 输入文件
-out 输出文件
openssl x509 -in icbc_rsa.cer -out icbc_rsa.txt -text

结果：
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6c:82:ca:10:24:96:00:29:9c:49
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: CN = ICBC Test Personal CA, O = personaltest.icbc.com.cn
        Validity
            Not Before: Nov 25 07:45:12 2019 GMT
            Not After : Nov 25 15:59:59 2024 GMT
        Subject: CN = 360200274427634.p.3602, OU = 3602, O = personaltest.icbc.com.cn
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (1024 bit)
                Modulus:
                    00:f1:01:f0:ee:6c:3e:ea:8d:48:23:5a:21:99:14:
                    09:80:b2:b8:ba:42:e5:0e:ff:ef:33:d4:5c:e3:5f:
                    ec:52:d1:5b:13:c0:d5:f6:ea:9e:7d:a1:33:fa:02:
                    fe:bd:d5:fb:33:d2:55:b2:6c:c1:3c:88:61:32:37:
                    3e:bc:8a:36:a2:86:4c:99:be:01:e8:4e:b9:9f:92:
                    12:a9:01:32:e3:fe:b2:7a:88:11:07:40:67:c9:69:
                    f9:3a:60:59:60:72:13:11:8f:f7:ad:47:a0:d6:a7:
                    96:01:60:22:19:84:aa:11:30:ad:63:51:d0:a1:d3:
                    16:d7:2a:2f:a3:48:10:cd:0d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                keyid:76:F9:60:A6:1D:E6:99:24:D5:F2:80:D6:87:D9:4E:A8:4B:FF:B9:51

            X509v3 CRL Distribution Points: 

                Full Name:
                  DirName:CN = crl546, OU = crl, O = personaltest.icbc.com.cn

            X509v3 Subject Key Identifier: 
                AA:A2:9C:AA:1C:74:29:F6:2E:DF:DC:B8:11:85:94:57:66:8A:60:57
    Signature Algorithm: sha1WithRSAEncryption
         56:5b:fb:80:e2:12:e2:0d:97:07:b5:e3:c7:a6:b4:67:52:24:
         38:11:b0:ba:ff:2a:92:20:c3:77:77:19:d4:7f:74:74:35:18:
         99:64:71:5b:1e:c2:71:3a:44:d9:bf:a4:49:fd:2b:da:cc:de:
         bf:be:dc:74:3d:a8:0e:81:4d:0a:1a:e2:b1:28:b6:12:4a:61:
         79:b4:f9:1f:d2:2c:9b:40:34:4f:a7:13:bd:7b:1a:da:40:21:
         8d:44:dc:58:f7:26:d3:17:68:03:82:fc:6c:72:7a:fc:fa:26:
         7d:7e:94:60:0a:41:92:99:f4:fd:c0:db:12:fa:ed:f3:67:eb:
         db:5a:79:c6:81:4c:fa:33:ca:1c:0d:e4:e4:6b:e1:14:d7:5a:
         9e:85:25:aa:d0:d2:50:99:61:a2:cc:4b:32:3f:ee:65:b7:b4:
         4c:c5:19:d7:0a:2e:ca:ce:69:46:f5:5b:64:86:68:c8:db:fb:
         c7:ac:2a:cb:1b:7c:27:b0:b5:7a:f8:85:3c:72:bb:15:ca:4e:
         e0:35:bf:51:31:e1:d0:44:c7:ba:41:f8:61:a1:52:42:2d:64:
         52:42:45:62:7c:56:33:ad:0b:56:d2:67:d3:78:c0:0f:8a:c4:
         0a:f4:e9:1b:45:10:c0:22:26:5d:94:09:44:03:7d:d7:c1:89:
         85:3f:e7:f3
```

```
解析命令
-in 输入文件
-out 输出文件
openssl x509 -in netca.cer -out netca.txt -text

    Data:
        Version: 3 (0x2)
        Serial Number:
            10:e1:11:9b:0d:78:0a:3c:f3:05:3b
        Signature Algorithm: 1.2.156.10197.1.501
        Issuer: C = CN, O = NETCA Certificate Authority, CN = NETCA SM2 TEST01 and Evaluation CA01
        Validity
            Not Before: Sep 25 09:04:26 2018 GMT
            Not After : Sep 25 09:04:26 2021 GMT
        Subject: C = CN, ST = Guangdong, L = \E5\B9\BF\E5\B7\9E\E5\B8\82\E5\A4\A9\E6\B2\B3\E5\8C\BA\E4\BA\94\E5\B1\B1\E8\B7\AF246\E3\80\81248\E3\80\81250\E5\8F\B7302\E8\87\AA\E7\BC\9601C, O = \E5\B9\BF\E5\B7\9E\E7\84\B6\E6\80\A1\E8\BD\AF\E4\BB\B6\E6\9C\89\E9\99\90\E5\85\AC\E5\8F\B8, CN = \E5\B9\BF\E5\B7\9E\E7\84\B6\E6\80\A1\E8\BD\AF\E4\BB\B6\E6\9C\89\E9\99\90\E5\85\AC\E5\8F\B8
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:ea:27:31:27:ce:1d:45:fe:ce:fb:db:18:76:cc:
                    91:f2:9e:03:95:f7:5f:96:2c:57:c3:07:e5:7f:cf:
                    39:58:a7:a0:c1:a4:40:22:ee:8d:6f:92:93:93:74:
                    9e:59:85:90:51:c6:63:11:a8:49:38:cd:42:98:71:
                    b9:9d:fd:35:9a
                ASN1 OID: SM2
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                46:F1:FF:54:72:C5:6E:4D:DD:2C:F0:E8:8D:0E:94:8A:95:55:E8:88
            X509v3 Authority Key Identifier: 
                keyid:0C:7B:EB:62:73:03:75:FA:8C:4A:24:0C:F6:8F:3B:21:65:7E:17:E9

            X509v3 Certificate Policies: 
                Policy: 1.3.6.1.4.1.18760.13.10
                  CPS: http://www.cnca.net/cs/knowledge/whitepaper/cps/netCAtestcertcps.pdf

            X509v3 CRL Distribution Points: 

                Full Name:
                  URI:http://test.cnca.net/crl/SM2CA.crl

            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation
            1.3.6.1.4.1.18760.1.14: 
                .$bf86d4e64b664d84deabccb6baa898bf@S02
    Signature Algorithm: 1.2.156.10197.1.501
         30:45:02:21:00:a5:40:8b:40:17:41:53:d0:f1:4e:3c:25:61:
         e7:98:ac:76:da:e1:f2:05:0a:01:8d:3d:c2:0a:e7:5d:a8:88:
         c1:02:20:15:64:98:1a:72:3a:bb:54:f3:fb:23:f3:67:b8:e0:
         da:07:a6:9f:0a:70:c4:e6:6f:c9:07:30:44:3f:c0:b2:77
```

## 用c++来解码

## 实验效果图

用SM2签名的算法

![](/images/20200928/0.png)

用RSA签名的算法

![](/images/20200928/1.png)

<https://www.cnblogs.com/jiu0821/p/4598352.html>

<https://blog.csdn.net/think_A_lot/article/details/86326604>

解码RSA算法加密的证书的代码

```
#include "decodeX509Cert.h"

int main() {
    X509Reader reader;
    reader.loadFile("netSm2.der");
    reader.compileContent();
    reader.showX509();
    reader.displayResult();
    return 0;
}

#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <cstdlib>

using namespace std;

/*
1、序列号
2、签名算法
3、使用者
4、公钥
5、有效期开始，有效期结束 时间
*/
struct Seg {
    int num;
    Seg(unsigned char s) {
        num = (int)s;
    };
    Seg() {
        num = -1;
    }
};

typedef struct Seg Seg;

struct TLV {
    Seg type;
    vector<Seg> length;
    vector<Seg> value;
};

typedef struct TLV TLV;

struct SignatureAlgorithm {
    TLV algorithm;
    TLV parameters;
};

struct subjectPublicKey {
    TLV algorithm;
    TLV parameters;
    TLV PKey;
};

struct SignatureValue {
    TLV signatureValue;
};

struct signatureArray {
    TLV s1, s2;
};

typedef struct SignatureAlgorithm SignatureAlgorithm;
typedef struct subjectPublicKey subjectPublicKey;
typedef struct SignatureValue SignatureValue;
typedef struct signatureArray signatureArray;

struct TbsCertificate {
    TLV version;
    TLV serialNumber;
    SignatureAlgorithm signature;
    vector<signatureArray> issuer_;
    vector<TLV> validity;
    vector<signatureArray> subject_;
    subjectPublicKey subjectPublicKeyInfo;
    TLV issuerUniqueID;
    TLV subjectUniqueID;
    vector<TLV> extensions;
};

struct X509cer {
    struct TbsCertificate catb;
    struct SignatureAlgorithm casa;
    struct SignatureValue casv;
};

class X509Reader {
private:
    vector<Seg> segList;
    vector<TLV> tlvList;
    struct X509cer x509cert;
    map<string, string> OIDMap;
public:
    X509Reader() {
        OIDMap.insert(pair<string, string>("1.2.840.10040.4.1", "DSA"));
        OIDMap.insert(pair<string, string>("1.2.840.10040.4.3", "sha1DSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.1", "RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.2", "md2RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.3", "md4RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.4", "md5RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.5", "sha1RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.113549.1.1.11", "sha256RSA"));
        OIDMap.insert(pair<string, string>("1.2.840.10045.2.1", "ECC"));
        OIDMap.insert(pair<string, string>("1.2.840.10045.3.1.7", "ECDSA_P256"));
        OIDMap.insert(pair<string, string>("1.2.156.10197.1.501", "SM2"));

        OIDMap.insert(pair<string, string>("2.5.4.6", "C"));
        OIDMap.insert(pair<string, string>("2.5.4.8", "S"));
        OIDMap.insert(pair<string, string>("2.5.4.7", "L"));
        OIDMap.insert(pair<string, string>("2.5.4.10", "O"));
        OIDMap.insert(pair<string, string>("2.5.4.11", "OU"));
        OIDMap.insert(pair<string, string>("2.5.4.3", "CN"));
    }

    void loadFile(string filename) {
        std::ifstream file;
        file.open(filename.c_str(), ios::in | ios::binary);
        while (!file.eof()) {
            char first;
            file.read(&first, 1);
            segList.push_back(Seg((unsigned char)first));
        }
        file.close();
    }
    //把文本的所有字节解释成tlv结构保存在tlvlist中
    void compileContent() {
        //由于要访问i+1的地址，所以i只能到size-1
        for (int i = 0; i < segList.size() - 1; ) {
            //如果是context-specific类型的数据
            if (segList[i].num >> 6 == 2) {
                int n = segList[i].num & 0x1f;
                //如果是3，表示扩展字段
                if (n == 3) {
                    TLV t;
                    t.type = segList[i];
                    if (segList[i + 1].num <= 0x7f) {
                        t.length.push_back(segList[i + 1]);
                        i += 2;
                    }
                    else {
                        int l = segList[i + 1].num - 0x80;
                        int s = 0, base = 1;
                        for (int j = i + 2 + l - 1; j >= i + 2; j--) {
                            s += segList[j].num * base;
                            base *= 256;
                        }
                        for (int j = i + 1; j < i + 2 + l; j++) {
                            t.length.push_back(segList[j]);
                        }
                        i += 2 + l;
                    }
                    tlvList.push_back(t);
                }
                else {
                    TLV t;
                    t.type = segList[i];
                    t.length.push_back(segList[i + 1]);
                    tlvList.push_back(t);
                    i += 2;
                }
            }
            //如果是结构类型的数据
            else {
                if (segList[i].num >> 5 == 1) {
                    TLV t;
                    t.type = segList[i];
                    //如果该类型的长度小于127，用一个字节表示长度
                    if (segList[i + 1].num <= 0x7f) {
                        t.length.push_back(segList[i + 1]);
                        i += 2;
                    }
                    //否则，用多个字节表示长度
                    else {
                        //l记录长度由多少个字节表示
                        int l = segList[i + 1].num - 0x80;
                        //s记录长度值
                        int s = 0, base = 1;
                        for (int j = i + 2 + l - 1; j >= i + 2; j--) {
                            s += segList[j].num * base;
                            base *= 256;
                        }
                        //把表示长度的字节放入tlv结构中的length中
                        for (int j = i + 1; j < i + 2 + l; j++) {
                            t.length.push_back(segList[j]);
                        }
                        //偏移2+L
                        i += 2 + l;
                    }
                    tlvList.push_back(t);
                }
                //其他类型的数据，如简单类型
                else {
                    TLV t;
                    t.type = segList[i];
                    if (segList[i + 1].num <= 0x7f) {
                        t.length.push_back(segList[i + 1]);
                        for (int j = i + 2; j < i + 2 + segList[i + 1].num; j++) {
                            t.value.push_back(segList[j]);
                        }
                        i += segList[i + 1].num + 2;
                    }
                    else {
                        int l = segList[i + 1].num - 0x80;
                        int s = 0, base = 1;
                        for (int j = i + 2 + l - 1; j >= i + 2; j--) {
                            s += segList[j].num * base;
                            base *= 256;
                        }
                        for (int j = i + 1; j < i + 2 + l; j++) {
                            t.length.push_back(segList[j]);
                        }
                        for (int j = i + 2 + l; j < i + 2 + l + s; j++) {
                            t.value.push_back(segList[j]);
                        }
                        i += 2 + l + s;
                    }
                    tlvList.push_back(t);
                }
            }
        }
    }
    //把tlvlist里面的信息段，转化成证书类x509cert里面的信息
    void showX509() {
        //count记录证书的第几部分信息
        int count = 0, extensionSize = 0;
        bool isExtension = false;
        bool isBlock31 = false;
        for (int i = 0; i < tlvList.size() - 1; i++) {
            if (isExtension) {
                //计算扩展部分的长度还剩下多少
                extensionSize -= 1 + tlvList[i].length.size() + tlvList[i].value.size();
            }
            //如果是SET类型
            if (tlvList[i].type.num == 0x31) {
                isBlock31 = true;
                continue;
            }
            else {
                //如果是SEQUENCE类型，且没有在SET里面时
                if (tlvList[i].type.num == 0x30 && isBlock31 == false) {
                    count++;
                    continue;
                }
                else if (tlvList[i].type.num == 0x30 && isBlock31 == true) {
                    isBlock31 = false;
                    continue;
                }
                //如果是证书的扩展字段
                else if (tlvList[i].type.num == 0xa3) {
                    count++;
                    isExtension = true;
                    int base = 1;
                    for (int j = tlvList[i].length.size() - 1; j >= 1; j--) {
                        extensionSize += tlvList[i].length[j].num * base;
                        base *= 256;
                    }
                    continue;
                }
            }
            //第二个SEQUENCE，版本信息，证书序号，一个SEQUENCE类型，对应一段信息
            if (count == 2) {
                if (tlvList[i].type.num == 0xa0) {
                    x509cert.catb.version = tlvList[i + 1];
                    i++;
                }
                else {
                    x509cert.catb.serialNumber = tlvList[i];
                }
            }
            //第3个SEQUENCE，证书签名算法标识，和参数
            else if (count == 3) {
                if (tlvList[i].type.num == 0x06) {
                    x509cert.catb.signature.algorithm = tlvList[i];
                }
                else {
                    x509cert.catb.signature.parameters = tlvList[i];
                }
            }
            //证书发行者名称
            else if (count == 4) {
                signatureArray a;
                if (tlvList[i].type.num == 0x06) {
                    a.s1 = tlvList[i];
                    a.s2 = tlvList[i + 1];
                    x509cert.catb.issuer_.push_back(a);
                    i += 1;
                }
            }
            //证书有效期
            else if (count == 5) {
                x509cert.catb.validity.push_back(tlvList[i]);
                x509cert.catb.validity.push_back(tlvList[i + 1]);
                i += 1;
            }
            //证书主题名称
            else if (count == 6) {
                signatureArray a;
                if (tlvList[i].type.num == 0x06) {
                    a.s1 = tlvList[i];
                    a.s2 = tlvList[i + 1];
                    x509cert.catb.subject_.push_back(a);
                    i += 1;
                }
            }
            //count=7 没有信息
            //证书公钥信息
            else if (count == 8) {
                if (tlvList[i].type.num == 0x06) {
                    subjectPublicKey sbk;
                    sbk.algorithm = tlvList[i];
                    sbk.parameters = tlvList[i + 1];
                    sbk.PKey = tlvList[i + 2];
                    x509cert.catb.subjectPublicKeyInfo = sbk;
                    i += 2;
                }
            }
            //证书扩展部分
            else if (count >= 9 && isExtension) {
                if (extensionSize >= 0) {
                    x509cert.catb.extensions.push_back(tlvList[i]);
                }
                if (extensionSize == 0) {
                    isExtension = false;
                }
            }
            //最后，证书签名算法标志，签名值
            else {
                if (tlvList[i].type.num == 0x06) {
                    if (formatOID(x509cert.catb.signature.algorithm)._Equal("SM2")) {
                        x509cert.casa.algorithm = tlvList[i];
                        x509cert.casv.signatureValue = tlvList[i + 1];
                        i += 1;
                        
                    }
                    else {
                        x509cert.casa.algorithm = tlvList[i];
                        x509cert.casa.parameters = tlvList[i + 1];
                        x509cert.casv.signatureValue = tlvList[i + 2];
                        i += 2;
                    }
                    
                }
            }
        }
    }
    //有效时间的输出
    string formatDate(TLV& p) {
        string result = "20";
        if (p.type.num == 0x17) {
            int count = 0;
            for (int i = 0; i < p.value.size() - 1; i += 2) {
                //根据ASCII码表转化成正常时间
                result = result + (char)p.value[i].num + (char)p.value[i + 1].num;
                if (count <= 1) {
                    result += "/";
                }
                else if (count == 2) {
                    result += " ";
                }
                else if (count <= 4) {
                    result += ":";
                }
                count++;
            }
            return result + " GMT";
        }
        else {
            return "";
        }
    }
    //对OID进行还原
    string formatOID(TLV& p) {
        string result = "";
        char num[9];
        vector<int> V;
        //如果是OBJECT IDENTIFIER类型
        if (p.type.num == 0x06) {
            for (int i = 0; i < p.value.size(); i++) {
                //第一个字节
                if (i == 0) {
                    int v2 = p.value[i].num % 40;
                    int v1 = (p.value[i].num - v2) / 40;
                    V.push_back(v1);
                    V.push_back(v2);
                }

                else {
                    int j = i, res = 0;
                    int base = 128;
                    //如果大于等于128，那么该字节不是最后一位
                    while (p.value[j].num >= 0x80) {
                        j++;
                    }
                    //计算出被表示值
                    res = p.value[j].num;
                    for (int k = j - 1; k >= i; k--) {
                        res += (p.value[k].num - 0x80) * base;
                        base *= 128;
                    }
                    V.push_back(res);
                    i = j;
                }
            }
            //拼凑成oid标识串，并且在hash表中找到相应名
            for (int i = 0; i < V.size(); i++) {
                sprintf(num, "%d", V[i]);
                result += num;
                if (i < V.size() - 1) {
                    result += ".";
                }
            }
            return OIDMap[result];
        }
        else {
            return "";
        }
    }
    //输出segList的十六进制表示
    void displayOrigin() {
        int count = 0;
        for (int i = 0; i < segList.size(); i++) {
            printf("%02x ", segList[i].num);
            count++;
            if (count == 16) {
                cout << endl;
                count = 0;
            }
        }
    }
    //输出tlvList里面的内容
    void displayTLVOrigin() {
        int count = 0;
        bool isBlock31 = false;
        for (int i = 0; i < tlvList.size(); i++) {
            if (tlvList[i].type.num == 0x31) {
                isBlock31 = true;
            }
            else {
                if (tlvList[i].type.num == 0x30 && isBlock31 == false) {
                    count++;
                }
                else if (tlvList[i].type.num == 0x30 && isBlock31 == true) {
                    isBlock31 = false;
                }
                else if (tlvList[i].type.num == 0xa3) {
                    count++;
                }
            }
            cout << "Count: " << count << endl;
            printf("type: %02x ", tlvList[i].type);
            printf("length: ");
            for (int j = 0; j < tlvList[i].length.size(); j++) {
                printf("%02x ", tlvList[i].length[j]);
            }
            printf("value(%02x): ", tlvList[i].value.size());
            for (int j = 0; j < tlvList[i].value.size(); j++) {
                printf("%02x ", tlvList[i].value[j]);
            }
            printf("\n");
        }
    }

    void printValue(TLV& p, int mode = 0) {
        if (p.value.size() == 0) {
            printf("NULL");
        }
        else {
            for (int i = 0; i < p.value.size(); i++) {
                //如果时BIG STRING类型，那么把前面没用的那个字节省略掉
                if (p.type.num == 0x03 && i == 0) continue;
                //如果是表示ASCII码的类型，那么按字符输出
                if (p.type.num == 0x13 || p.type.num == 0x0c) {
                    printf("%c", p.value[i].num);
                }
                //否则按十六进制输出
                else {
                    //如果没指定参数，有空格输出
                    if (mode == 0) {
                        printf("%02x ", p.value[i].num);
                    }
                    else {
                        printf("%02x", p.value[i].num);
                    }
                }

            }
            //如果是表示ASCII码的类型
            if (p.type.num == 0x0c) {
                printf("(UTF-8)");
            }
        }
        printf("\n");
    }

    void displayResult() {
        printf("SerialNumber: ");
        printValue(x509cert.catb.serialNumber, 1);
        printf("SignatureAlgorithm: ");
        cout << formatOID(x509cert.catb.signature.algorithm) << endl;
        printf("Subject:\n");
        for (int i = 0; i < x509cert.catb.subject_.size(); i++) {
            cout << "    " << formatOID(x509cert.catb.subject_[i].s1);
            printf(" = ");
            printValue(x509cert.catb.subject_[i].s2);
        }
        printf("Validity:\n    notBefore: ");
        cout << formatDate(x509cert.catb.validity[0]) << endl;
        printf("    notAfter: ");
        cout << formatDate(x509cert.catb.validity[1]) << endl;

        /*其他信息
        printf("        PKey: ");
        printValue(x509cert.catb.subjectPublicKeyInfo.PKey);




        printf("Version: V%d\n", x509cert.catb.version.value[0].num + 1);

        
        printf("    Params: ");
        printValue(x509cert.catb.signature.parameters);
        printf("Issuer: \n");
        for (int i = 0; i < x509cert.catb.issuer_.size(); i++) {
            cout << "    " << formatOID(x509cert.catb.issuer_[i].s1);
            printf(" = ");
            printValue(x509cert.catb.issuer_[i].s2);
        }
        
        
        printf("subjectPublicKeyInfo:\n");
        //公钥算法
        printf("    Algorithm: ");
        cout << formatOID(x509cert.catb.subjectPublicKeyInfo.algorithm) << endl;
        printf("        Params: ");
        printValue(x509cert.catb.subjectPublicKeyInfo.parameters);
        

        printf("issuerUniqueID: ");
        printValue(x509cert.catb.issuerUniqueID);
        printf("subjectUniqueID: ");
        printValue(x509cert.catb.subjectUniqueID);
        printf("Extensions:\n");
        printf("    Other: ellipsis\n");
        /* 拓展部分不翻译
        for(int i = 0; i < x509cert.catb.extensions.size(); i++) {
            if(x509cert.catb.extensions[i].type.num == 0x01) {
                printf("    isCACertification: ");
                printValue(x509cert.catb.extensions[i]);
                printf("    Other: ellipsis\n");
                break;
            }
        }
        printf("SignatureAlgorithm:\n");
        printf("    Algorithm: ");
        cout << formatOID(x509cert.casa.algorithm) << endl;
        printf("    Params: ");
        printValue(x509cert.casa.parameters);
        printf("SignatureValue: ");
        printValue(x509cert.casv.signatureValue);
        */
    }
};


```



## 算法描述

1）、打开一个二进制的证书文件，按字节把文件中所有字节读入到字符容器中

2）、
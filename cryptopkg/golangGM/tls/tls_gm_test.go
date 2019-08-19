package tls

import (
	"encoding/pem"
	"fmt"
	"testing"
)



var sm2KeyPEM = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgiBD15Oh7u8WvoNgQ
GbePEPjWhuNK5z0ZPWY1egMWw/6gCgYIKoEcz1UBgi2hRANCAASAx358+DUun/v7
QjNMx7PlX//TzTU4ef0r56IUOVu6fSoLxPusYsty7MHMT4KM1RF6Fz7CFtZLBUAM
HxFTp0QZ
-----END PRIVATE KEY-----
`
//此处的" ` "号一定要空换行再写,否则pem.Decode(certPEMBlock)解析会解析错误

var sm2CertPEM =`-----BEGIN CERTIFICATE-----
MIIEDDCCA7KgAwIBAgIB/zAKBggqgRzPVQGDdTBLMRAwDgYDVQQKEwdDaGluYXNv
MRkwFwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMQ8wDQYDVQQqEwZHb3BoZXIxCzAJ
BgNVBAYTAk5MMB4XDTcwMDEwMTAwMTY0MFoXDTcwMDEwMjAzNDY0MFowSzEQMA4G
A1UEChMHQ2hpbmFzbzEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTEPMA0GA1UE
KhMGR29waGVyMQswCQYDVQQGEwJOTDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IA
BIDHfnz4NS6f+/tCM0zHs+Vf/9PNNTh5/SvnohQ5W7p9KgvE+6xiy3LswcxPgozV
EXoXPsIW1ksFQAwfEVOnRBmjggKFMIICgTAOBgNVHQ8BAf8EBAMCAgQwJgYDVR0l
BB8wHQYIKwYBBQUHAwIGCCsGAQUFBwMBBgIqAwYDgQsBMA8GA1UdEwEB/wQFMAMB
Af8wXwYIKwYBBQUHAQEEUzBRMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5leGFt
cGxlLmNvbTAqBggrBgEFBQcwAoYeaHR0cDovL2NydC5leGFtcGxlLmNvbS9jYTEu
Y3J0MGIGA1UdEQRbMFmCEHRlc3QuZXhhbXBsZS5jb22BEWdvcGhlckBnb2xhbmcu
b3JnhwR/AAABhxAgAUhgAAAgAQAAAAAAAABohhpodHRwczovL2Zvby5jb20vd2li
YmxlI2ZvbzAPBgNVHSAECDAGMAQGAioDMIHfBgNVHR4EgdcwgdSgYTAOggwuZXhh
bXBsZS5jb20wDYILZXhhbXBsZS5jb20wCocIwKgAAP//AAAwCocIAQAAAP8AAAAw
EYEPZm9vQGV4YW1wbGUuY29tMAqGCC5iYXIuY29tMAmGB2Jhci5jb22hbzARgg9i
YXIuZXhhbXBsZS5jb20wIocgIAENuAAAAAAAAAAAAAAAAP///////wAAAAAAAAAA
AAAwDoEMLmV4YW1wbGUuY29tMA2BC2V4YW1wbGUuY29tMAuGCS5iYXIyLmNvbTAK
hghiYXIyLmNvbTBXBgNVHR8EUDBOMCWgI6Ahhh9odHRwOi8vY3JsMS5leGFtcGxl
LmNvbS9jYTEuY3JsMCWgI6Ahhh9odHRwOi8vY3JsMi5leGFtcGxlLmNvbS9jYTEu
Y3JsMBYGAyoDBAQPZXh0cmEgZXh0ZW5zaW9uMA0GA1UdDgQGBAQEAwIBMAoGCCqB
HM9VAYN1A0gAMEUCIHdFmmNUQlqw0zeelxZanLfRu4b2cVeXPOS9Y7ZIuna1AiEA
yK7ndPHOtTxPLwujxM2K8pzF43usNg87Njgk8PewGts=
-----END CERTIFICATE-----
`



var keyPairgmTests = []struct {
	algo string
	cert string
	key  string
}{


	{"SM2", sm2CertPEM, sm2KeyPEM},
}


func TestReadCertificateFromPem(t *testing.T) {

	certDERBlock, _ := pem.Decode([]byte(sm2CertPEM))
	fmt.Println("certDERBlock.Type",certDERBlock.Type)
}

func TestReadCertificateFromPem2(t *testing.T) {

	certDERBlock, _ := pem.Decode([]byte(sm2CertPEM + sm2KeyPEM))//此种方式在pem.Decode解码时出错
	//fmt.Println("certDERBlock.Type",certDERBlock.Type)  // 这会使得 certDERBlock == nil 跳出for循环,此时没有certDERBlock.Type的概念,打印此参数当然会报错
	fmt.Println("certDERBlock",certDERBlock)  //正常情况下这个certDERBlock应该不为空的

	fmt.Println("[]byte(sm2CertPEM + sm2KeyPEM)",[]byte(sm2CertPEM + sm2KeyPEM))

}

func TestX509KeyPairgm1(t *testing.T) {
	t.Parallel()
	var pem []byte
	for _, test := range keyPairgmTests {
	pem=[]byte(test.cert+test.key)
	//fmt.Println("test.cert",[]byte(test.cert) )
    //fmt.Println("test.key",[]byte(test.key) )
    //fmt.Println("pem",pem )
	_, err :=X509KeyPair(pem, pem)

	fmt.Println("err",err)
	}
}

func TestX509KeyPairgm(t *testing.T) {
	t.Parallel()
	var pem []byte
	for _, test := range keyPairgmTests {
		pem = []byte(test.cert + test.key)
		//pem=[]byte(test.cert )
		//X509KeyPair(pem, pem)

		if _, err := X509KeyPair(pem, pem); err != nil {
			t.Errorf("Failed to load %s cert followed by %s key: %s", test.algo, test.algo, err)
		}
		pem = []byte(test.key + test.cert)
		if _, err := X509KeyPair(pem, pem); err != nil {
			t.Errorf("Failed to load %s key followed by %s cert: %s", test.algo, test.algo, err)
		}
	}
}
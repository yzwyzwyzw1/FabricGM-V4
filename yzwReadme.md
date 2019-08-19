

备忘录:common/tools/gmidemixgen/idemixca/idemixca_test.go 

assert.NoError(t, setupMSP()) 报错!



只要想办法生成支持国密的fabric镜像,所有的问题就将都能解决!

orderer 目录下
- orderer/common/msgprocessor 
orderer/common/server/server.go引用

- orderer/common/multichannel
需要修改

orderer/common/gmmsgprocessor该文件夹可删除


"github.com/chinaso/fabricGM/orderer/common/cluster"涉及crypto/x509,所以必须修改以兼容国密
这个文件夹中的内容除自身文件夹中的程序调用以外,外部调用的程序有,etcdraft/consenter.go , etcdraft/chain.go, server /main.go, server/onboarding.go


对common文件夹的修改
1.添加了文件common/attrmgr/gmattrmgr.go


core/comm/client.go  NewGRPCClient 主要在peer程序中使用


msp_test.go在执行的时候,一定执行了TestMain函数,用于先域其他模块执行环境测试

bccsp/idemix/handlers/nym.go public() 我写死了使用sha256

bccsp/idemix/handlers/revocation_x.go 我写死了使用sha256




- bccsp/idemix待测试


- common/tools/idemixgen/idemixca/idemixca.go   :56行 idemix.HashModOrder被我修改过


- peer/node/start.go中663行使用了调用core.accesscontrol.NewAuthenticator,而这个函数中使用了sha256算法.也是需要替换的,替换完之后需要修改peer中的内容peer/node/start.go
authenticator := accesscontrol.NewAuthenticator(ca)   


- common/util/utils.go 新增ComputeSM3函数

- bccsp/factory/opts_x.go 对GetDefaultOpts()函数做了修改,必要时需要再修改回来

- 对/home/yzw/GoSpace/gopath/src/github.com/chinaso/fabricGM/vendor/google.golang.org/grpc 下的导包"google.golang.org/grpc/credentials"统一修改为了"github.com/chinaso/fabricGM/cryptopkg/golangGM/grpc/credentials"
crypto/tls --> github.com/chinaso/fabricGM/cryptopkg/golangGM/tls      
 
- core/comm/config.go中配置了默认的tls密码套件

- core/comm/util_x.go文件中新增GMExtractCertificateHashFromContext函数,这个函数在discovery/service.go的第89行被引用,要注意修改


- orderer/consensus/kafka/config.go导入了包文件vendor/github.com/Shopify/sarama,该程序中使用了crypto/tls这与orderer/consensus/kafka/config.go使用的国密版tls存在包冲突,解决办法是,修改vendor/github.com/Shopify/sarama/blocker.go程序中的crypto/tls为
我修改的国密版tls包
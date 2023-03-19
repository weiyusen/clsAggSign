// const secp = require('./secp265k1');
const secp = require('./secp265k1.min');
(async () => {
    const PID = secp.utils.randomPID()  // 假名
    const userSecret = secp.utils.randomPrivateKey()  // 用户秘密值  x
    const userPublic = secp.certificateless.getPublicKey(userSecret)  // 用户公钥 X=x*P

    const systemSectrtKey = secp.utils.randomPrivateKey()  // 系统私钥  s
    const systemPublic = secp.certificateless.getPublicKey(systemSectrtKey) //系统公钥  Ppub
    // Uint8Array(64)  N的横坐标 + 部分私钥   d=n+H(PID,Q,Ppub)*s  其中Q=N+X=(n+x)*P
    const {partialSecretKeyArray, NPointArray} = await secp.certificateless.getPartialKey(PID, userPublic, systemSectrtKey)  
    
    // 设置公钥Q=X+N
    const Qpoint = secp.certificateless.setPublicKey(NPointArray, userPublic)
    // 验证 dP=Q+H(PID,Q,Ppub)*Ppub
    const res = await secp.certificateless.verifyPartialKey(partialSecretKeyArray, Qpoint,NPointArray, systemPublic,PID)
    console.log('部分私钥验证结果',res)
    // 无证书签名  σ=d+x+h2*u    h2=H(pid,Q,Ppub,m,U)
    const message = await secp.utils.sha256('hello world');
    const {certificatelessSignatutreArray, UPointArray} = await secp.certificateless.certificatelessSign(partialSecretKeyArray, userSecret, PID, Qpoint,systemPublic,message)
    // 无证书签名验证
    const verifyResult = await secp.certificateless.certificatelessVerify(certificatelessSignatutreArray,PID,Qpoint,systemPublic,message,UPointArray)
    console.log('单一签名验证结果',verifyResult)

    // 无证书聚合签名
    const messageOne = await secp.utils.sha256('One')
    const messageTwo = await secp.utils.sha256('Two')
    const messageThree = await secp.utils.sha256('Three')
    const {certificatelessSignatutreArray : sigOne, UPointArray :Uone} = await secp.certificateless.certificatelessSign(partialSecretKeyArray, userSecret, PID, Qpoint,systemPublic,messageOne)
    const {certificatelessSignatutreArray : sigTwo, UPointArray :UTwo} = await secp.certificateless.certificatelessSign(partialSecretKeyArray, userSecret, PID, Qpoint,systemPublic,messageTwo)
    const {certificatelessSignatutreArray : sigThree, UPointArray :UThree} = await secp.certificateless.certificatelessSign(partialSecretKeyArray, userSecret, PID, Qpoint,systemPublic,messageThree)
    const sigList = [sigOne,sigTwo,sigThree]
    const messageList = [messageOne,messageTwo,messageThree]
    const UList = [Uone,UTwo,UThree]
    const PIDList = [PID,PID,PID]
    const QList = [Qpoint,Qpoint,Qpoint]
    const sigAgg = await secp.certificateless.certificatelessAggSign(sigList, UList, messageList, QList,PIDList,systemPublic)

    // 无证书聚合签名验证
    const aggSignVerifyResult = await secp.certificateless.certificatelessAggVerify(sigAgg, UList, messageList, QList,PIDList,systemPublic)
    console.log('聚合签名验证结果',aggSignVerifyResult)
  })();
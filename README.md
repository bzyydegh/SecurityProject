# SecurityProject
Java实现加解密之单向加密，对称和非对称加密，数字签名
## 三种实现方式
1.JDK 2.Commons Codec 3.Bouncy Castle
## 消息摘要算法
1.SHA 2.MD 3.MAC
## Base64算法
## 数字签名
1.RSA 2.DSA 3.ECDSA
## 遇到的问题及解决办法
### sun.misc.BASE64Encoder在Eclipse中不能直接使用的原因和解决方案
#### 1、为什么在Eclipse中不能直接使用sun.misc.BASE64Encoder和sun.misc.BASE64Decoder呢？
  因为sun.misc.BASE64Encoder和sun.misc.BASE64Decoder 是 Sun 的专用 API，可能会在未来版本中删除，不建议使用。
  所以在Eclipse中不能直接使用，但是直接使用文本编辑器编写代码，然后使用javac编译，Java去执行是没有问题的。
#### 2、通过以下设置就可以在Eclipse中使用了
  右击项目 --> Properties --> Java Build Path --> 点开JRE System Library --> 
  点击Access rules --> Edit --> Add --> Resolution选择Accessible --> Rule Pattern填上 ** --> OK
### “Illegal key size or default parameters”异常
  因为美国的出口限制，Sun通过权限文件（local_policy.jar、US_export_policy.jar）
  做了相应限制。因此存在一些问题。</br>
  解决办法参考：http://www.cnblogs.com/AloneSword/p/3487809.html

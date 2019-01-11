# DIMP
## server package
yum list available | grep pip
yum install python3-pip
pip install base58
yum install python34-pip.noarch
pip3 install --upgrade pip
pip3 install base58
pip3 install pycrypto
pip3 install Crypto
pip3 install --upgrade pycrypt
pip3.4 install Crypto
pip3.4 install --upgrade pycrypt
pip3 install pycryptodome
pip3 install rsa
pip3 install binascii

## 收发消息
发送方发送到服务器, 服务器保存至收件人文件夹内
开启另一个线程, 扫描收件人文件夹内新信息, 如果收件人在线, 则推送给收件人
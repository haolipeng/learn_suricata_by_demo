一、依赖库
cjson
yaml

二、网络流量捕获
    1.windows
        winpcap
        npcap

    2.linux
        pcap file
        AF_PACKET + MMAP

三、线程模型
agent端资源有限，所以采用run to complete线程模型

四、编程约定
先采用纯C编码，基础组件源于个人base库.业务逻辑需要的基础组件持续更新。

五、测试

在项目中引入gtest,从代码级别写代码进行测试

六、TODO事项

VxLan协议的解析没有实现协议识别和解析，以及展示相应字段
streaming buffer代码是放在dpi目录还是util目录更合适点呢？后面再讨论这个

先注释掉了所有的StreamTcpSetEvent函数
线程级别的ipv4、ipv6、tcp、udp、icmp数据包的个数，暂时未实现

前期仅实现了linux x86平台，暂时未实现windows平台和arm平台。
暂时是复用Packet结构体，后续采用Packet内存池的方式来实现（暂时未实现）

TODO:pcap模式下的流量采集，暂时还没有做
StatsIncr comment
StatsAddUI64 comment

StreamTcpSetEvent

ReassembleUpdateAppLayer
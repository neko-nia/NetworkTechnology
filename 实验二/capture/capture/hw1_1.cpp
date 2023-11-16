#define HAVE_REMOTE
#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>

#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数

#define _WINSOCK_DEPRECATED_NO_WARNINGS

using namespace std;
//以太网协议格式
#pragma pack(1)//进入字节对齐方式 分配地址时没有空余

struct e_header //以太网帧首部
{
	uint8_t e_dst[6];// 目标MAC地址
	uint8_t e_src[6];//源MAC地址
	uint16_t e_type;//以太网类型
	//以太网类型为0x0800（十六进制），那么它表示IP数据包。
};

struct ip_header //IP首部
{
	uint8_t ip_header_len : 4,//首部长度
		ip_ver : 4;//首部版本
	uint8_t tos;//服务类型
	uint16_t total_len;//总长度
	uint16_t ip_id;//标识
	uint16_t ip_offset;//片偏移
	uint8_t ttl;//生存时间
	uint8_t ip_protocol;//协议类型（TCP或者UDP协议）
	uint16_t ip_checksum;//首部检验和
	//struct表示一个32位的IPv4地址
	struct in_addr ip_src_addr; //源IP 
	struct in_addr ip_dst_addr; //目的IP
	uint16_t CCheckSum();//手动计算首部检验和

};
uint16_t ip_header::CCheckSum()
{
	uint32_t cal_checksum = 0;//存储计算校验和的中间值
	uint16_t var1 = (((this->ip_ver << 4) + this->ip_header_len) << 8) + this->tos;//计算了版本，首部长度，服务类型校验和部分
	uint16_t var2 = (this->ttl << 8) + this->ip_protocol;//计算了生存时间和IP协议的校验和部分
	uint16_t var3 = ntohl(this->ip_src_addr.S_un.S_addr) >> 16;//ntohl()将源IP长整形数从网络字节顺序转换为主机字节顺序，S_un.S_addr提供了IPv4地址的整数表示形式
	//将IP地址的前16位清零，从而得到源IP的主机字节序的IPv4地址。
	uint16_t var4 = ntohl(this->ip_src_addr.S_un.S_addr);//包含源IP地址的校验和部分
	uint16_t var5 = ntohl(this->ip_dst_addr.S_un.S_addr) >> 16;
	uint16_t var6 = ntohl(this->ip_dst_addr.S_un.S_addr);//包含目标IP地址的校验和部分
	cal_checksum = cal_checksum + var1 + ntohs(this->total_len) + ntohs(this->ip_id) + ntohs(this->ip_offset) + var2 + var3 + var4 + var5 + var6;
	cal_checksum = (cal_checksum >> 16) + (cal_checksum & 0xffff);//将 cal_checksum 右移16位，并将其与 0xffff进行按位与操作，以确保校验和的溢出部分被正确累加。
	cal_checksum += (cal_checksum >> 16);//处理可能的进位，将溢出部分再次加到 cal_checksum 中
	return (uint16_t)(~cal_checksum);
}

//IP数据包分析

void IPPacketAnalyse(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	ip_header* ip_protocol; // 初始化IP头
	uint32_t header_len; //数据包头长度
	uint16_t offset;//标志+片偏移  
	uint8_t tos;//服务类型
	uint16_t checksum;//首部检验和

	ip_protocol = (struct ip_header*)(packet_content + 14); //去掉以太网帧头部
	checksum = ntohs(ip_protocol->ip_checksum);//获得校验和
	header_len = ip_protocol->ip_header_len * 4; //获得长度
	tos = ip_protocol->tos;//获得tos
	offset = ntohs(ip_protocol->ip_offset);//获得偏移量
	cout << "===========解析IP层数据包======== " << endl;
	printf("IP版本:IPv%d\n", ip_protocol->ip_ver);
	cout << "IP协议首部长度:" << header_len << endl;
	printf("服务类型:%d\n", tos);
	cout << "数据包总长度:" << ntohs(ip_protocol->total_len) << endl;
	cout << "标识:" << ntohs(ip_protocol->ip_id) << endl;//将一个16位数由网络字节顺序转换为主机字节顺序(d大端小端)
	cout << "片偏移:" << (offset & 0x1fff) * 8 << endl;
	cout << "生存时间:" << int(ip_protocol->ttl) << endl;
	cout << "首部检验和:" << htons(checksum) << endl;
	cout << "(计算所得)首部检验和:" << htons(ip_protocol->CCheckSum()) << endl;
	char src[17];//存放源ip地址
	::inet_ntop(AF_INET, (const void*)&ip_protocol->ip_src_addr, src, 17);//将IP地址从二进制格式转换为文本格式的IP地址表示
	cout << "源IP地址:" << src << endl;
	char dst[17];//存放目的ip地址
	::inet_ntop(AF_INET, (const void*)&ip_protocol->ip_dst_addr, dst, 17);
	cout << "目的IP:" << dst << endl;
	printf("协议号:%d\n", ip_protocol->ip_protocol);
	cout << "传输层协议是:";
	switch (ip_protocol->ip_protocol)
	{
	case 1:
		cout << "ICMP" << endl;
		break;
	case 2:
		cout << "IGMP" << endl;
		break;
	case 3:
		cout << "GGP" << endl;
		break;
	case 6:
		cout << "TCP" << endl;
		break;
	case 8:
		cout << "EGP" << endl;
		break;
	case 17:
		cout << "UDP" << endl;
		break;
	case 89:
		cout << "OSPF" << endl;
		break;
	default:break;
	}
}

//解析数据链路层

void EPacketAnalyse(u_char* argument, const pcap_pkthdr* packet_header, const u_char* packet_content) {
	uint16_t E_type; //以太网协议类型
	e_header* E_protocol = (e_header*)packet_content;//以太网协议变量
	uint8_t* MAC_src;
	uint8_t* MAC_dst;
	static int packet_num = 1;//抓包数量

	E_type = ntohs(E_protocol->e_type); //获得以太网类型
	E_protocol = (e_header*)packet_content;//获得以太网协议数据内容
	MAC_src = E_protocol->e_src;//Mac源地址
	MAC_dst = E_protocol->e_dst;//Mac目的地址
	cout << "=========================================================" << endl;
	printf("第【 %d 】个IP数据包被捕获\n", packet_num);
	cout << "==========链路层协议==========" << endl;;
	printf("以太网类型为 :%04x\n",E_type);

	switch (E_type)//判断以太网类型的值
	{
	case 0x0800:
		cout << "网络层使用的是IPv4协议" << endl;
		break;
	case 0x0806:
		cout << "网络层使用的是ARP协议" << endl;
		break;
	case 0x8035:
		cout << "网络层使用的是RARP协议" << endl;
		break;
	default: break;
	}
	//获得Mac源地址
	printf("Mac源地址:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *MAC_src, *(MAC_src + 1), *(MAC_src + 2), *(MAC_src + 3), *(MAC_src + 4), *(MAC_src + 5));//X 表示以十六进制形式输出 02 表示不足两位，前面补0输出
	//获得Mac目的地址
	printf("Mac目的地址:\t%02x:%02x:%02x:%02x:%02x:%02x:\n", *MAC_dst, *(MAC_dst + 1), *(MAC_dst + 2), *(MAC_dst + 3), *(MAC_dst + 4), *(MAC_dst + 5));

	switch (E_type)
	{
	case 0x0800:
		/*如果上层是IPv4ip协议,就调用分析ip协议的函数对ip包进行贩治*/
		IPPacketAnalyse(argument, packet_header, packet_content);
		break;
	default:
		cout << "非IP数据包，不进行解析" << endl;
		break;
	}
	packet_num++;
}

void myCapture() {
	pcap_if_t* allAdapters; // 所有网卡设备保存
	pcap_if_t* p;// 用于遍历的指针
	pcap_t* pcap_handle;//打开网络适配器，捕捉实例,是pcap_open返回的对象
	int index = 0;//网卡序号
	int num = 0; //选择网卡
	int i = 0; //用于遍历链表
	char errbuf[PCAP_ERRBUF_SIZE];//错误缓冲区，大小为256

	int flag = 0;//过滤标志位
	char packet_filter[40] = ""; //用于存过滤条件 必须指定数组大小。不然会出现stack around the variable " " was corrupted报错
	struct bpf_program fcode;//指向 struct bpf_program 结构的指针，用于存储编译后的过滤器程序
	u_int netmask;//IPv4掩码

	// 获取网络适配器列表 
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
	{
		//打印适配器列表
		for (p = allAdapters; p != NULL; p = p->next)
		{
			++index;
			if (p->description)
				printf("编号 %d; %s \n", index, p->description);
		}
	}
	if (index == 0)
	{
		cout << "没有找到接口，请确认是否安装了Npcap或WinPcap" << endl;
	}
	cout << "请输入要获取哪个网卡的数据包" << endl;
	cin >> num;
	if (num < 1 || num > index)
	{
		cout << "网卡号违法" << endl;
		//释放设备列表
		pcap_freealldevs(allAdapters);
	}
	//找到要选择的网卡结构 
	for (p = allAdapters, i = 0; i < num - 1; p = p->next, i++);
	//打开选择的网卡
	if ((pcap_handle = pcap_open_live(p->name, //设备名称
		65536,//包长度最大值 65536允许整个包在所有mac电脑上被捕获
		PCAP_OPENFLAG_PROMISCUOUS,/* 混杂模式*/
		1000,//读超时为1秒
		errbuf//错误缓冲池
	)) == NULL)
	{
		cout << "无法打开适配器,Npcap不支持" << endl;
		//释放设备列表
		pcap_freealldevs(allAdapters);
		exit(0);
	}
	cout << "输入1：设置过滤条件 \n输入0:直接进行抓包" << endl;
	cin >> flag;
	if (flag == 1)
	{
		cout << "请设置过滤条件：";
		cin >> packet_filter;
		if (p->addresses != NULL) {
			/* 获取接口第一个地址的掩码 */
			netmask = ((struct sockaddr_in*)(p->addresses->netmask))->sin_addr.S_un.S_addr;
		}
		else {
			netmask = 0xffffff;//255.255.255.0
		}
		if (pcap_compile(pcap_handle, &fcode, packet_filter, 1, netmask) >= 0) {
			//设置过滤器
			if (pcap_setfilter(pcap_handle, &fcode) < 0)
			{
				cout << "过滤条件设置错误" << endl;
				exit(0);
			}
			cout << "正在抓包" << p->description << endl;
			//不再需要设备列表，释放
			pcap_freealldevs(allAdapters);
			int cnt = -1;//-1表示无限捕获，0表示捕获所有数据包，直到读取到EOF
			cout << "请输入想要捕获数据包的个数:" << endl;
			cin >> cnt;
			pcap_loop(pcap_handle, cnt, EPacketAnalyse, NULL);
			cout << "解析ip数据包结束" << endl;
		}
		else {
			cout << "过滤条件设置错误" << endl;
			exit(0);
		}
	}
	else {
		cout << "正在抓包" << p->description << endl;
		//不再需要设备列表，释放
		pcap_freealldevs(allAdapters);
		int cnt = -1;//-1表示无限捕获，0表示捕获所有数据包，直到读取到EOF
		cout << "请输入想要捕获数据包的个数:" << endl;
		cin >> cnt;
		pcap_loop(pcap_handle, cnt, EPacketAnalyse, NULL);
		cout << "解析ip数据包结束" << endl;
	}
}

int main() {
	myCapture();
	return 0;
}

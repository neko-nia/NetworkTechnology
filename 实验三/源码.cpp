#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include <pcap/pcap.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>

#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数
#define _WINSOCK_DEPRECATED_NO_WARNINGS
pcap_if_t* alldevs;//指向设备列表首部的指针
char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
pcap_addr_t* a;//用于遍历网络接口的地址信息
pcap_if_t* ptr;//用于遍历网络接口列表
pcap_t* pcap_handle;
struct pcap_pkthdr* pkt_header;//用于存储抓取到的数据包的头部信息
const u_char* pkt_data; //用于存储抓取到的数据包的头部数据
DWORD SendIP;
DWORD RevIP;
using namespace std;

void printMAC(BYTE MAC[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (i < 5)
			printf("%02x:", MAC[i]);
		else
			printf("%02x", MAC[i]);
	}
};
void printIP(DWORD IP)
{
	BYTE* p = (BYTE*)&IP;//将 IP 的地址强制转换为 BYTE 类型指针 p
	//将32位的IPv4地址拆分成4个8位的字节，以便逐个打印
	for (int i = 0; i < 4; i++)
	{
		if (i < 3) {
			cout << dec << (int)*p << ".";
			p++;
		}
		else
			cout << dec << (int)*p;
	}	
};
#pragma pack(1)
struct FrameHeader_t //帧首部
{
	BYTE DesMAC[6];  //目的地址
	BYTE SrcMAC[6];  //源地址
	WORD FrameType;  //帧类型
};
struct ARPFrame_t               //ARP帧
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
};
ARPFrame_t ARPFrame;//用于存储ARP帧
ARPFrame_t* IPPacket;//用于存储IP数据包
#pragma pack()        //恢复缺省对齐方式
void findalldevc() {
	int index = 0;//用于跟踪网络接口的索引
	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		cout << "获取网络接口时发生错误:" << errbuf << endl;
		return;
	}
	//显示接口列表
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		cout << "编号" << index + 1 << "\t" << ptr->description << endl;
		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			//筛选出IPv4地址
			if (a->addr->sa_family == AF_INET)
			{
				//inet_ntoa用于将IPv4地址（32位）转换为点分十进制字符串表示法
				cout << "IP地址：" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "子网掩码：" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;
			}
		}
		index++;
	}
}
void opennetwork() {
	int num;
	cout << "请选要打开的网卡号：";
	cin >> num;
	ptr = alldevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}
	pcap_handle = pcap_open(ptr->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//打开网卡
	if (pcap_handle == NULL)
	{
		cout << "打开网卡时发生错误：" << errbuf << endl;
		return ;
	}
	/*else
	{
		cout << "成功打开该网卡" << endl;
	}*/
}
void getip_mac(DWORD SendIP, DWORD RevIP) {
	while (true)
	{
		//使用 pcap_next_ex 函数来尝试捕获一个数据包
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			cout << "捕获数据包时发生错误：" << errbuf << endl;
			return ;
		}
		else
		{
			if (rtn == 0)
			{
				cout << "没有捕获到数据报" << endl;
			}

			else
			{
				IPPacket = (ARPFrame_t*)pkt_data;//将捕获到的数据包内容转换为 ARPFrame_t 类型的数据
				//假定捕获到的数据包是 ARP 请求或响应数据包
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//判断是不是一开始发的包
				//用来验证是否捕获到了与之前发送的ARP请求相匹配的ARP响应
				{

					cout << "      IP                       MAC" << endl;
					printIP(IPPacket->SendIP);
					cout << "	     	";
					printMAC(IPPacket->SendHa);
					cout << endl;
					break;
				}
			}
		}
	}
	return;
}
void ARPconsist() {
	//组装报文
	for (int i = 0; i < 6; i++)
	{
		//当发送 ARP 请求时此处全为1 (FF:FF:FF:FF:FF:FF)，即为广播地址。当发送 ARP 响应时，此处即为目的端 MAC 地址。
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//设置为本机广播地址255.255.255.255.255.255
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;//设置为虚拟的MAC地址66-66-66-66-66-66-66
		ARPFrame.RecvHa[i] = 0;//设置为0
		ARPFrame.SendHa[i] = 0x66;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4; // 协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	SendIP = ARPFrame.SendIP = htonl(0x70707070);//源IP地址设置为虚拟的IP地址 112.112.112.112
}
void filter() {
	//编译过滤器，只捕获ARP包
	u_int netmask;//用于存储子网掩码
	netmask = ((sockaddr_in*)(ptr->addresses->netmask))->sin_addr.S_un.S_addr;
	bpf_program fcode;//用于存储编译后的过滤器规则
	char packet_filter[] = "ether proto \\arp";//捕获以太网数据链路层上的ARP协议数据包
	//pcap_compile 函数将规则字符串 packet_filter 编译成一个 bpf_program 结构
	if (pcap_compile(pcap_handle, &fcode, packet_filter, 1, netmask) < 0)
	{
		cout << "无法编译数据包过滤器。检查语法";
		pcap_freealldevs(alldevs);
		return ;
	}
	//设置过滤器
	if (pcap_setfilter(pcap_handle, &fcode) < 0)
	{
		cout << "过滤器设置错误";
		pcap_freealldevs(alldevs);
		return ;
	}
}
void senddata() {
	//向网络发送数据包
	cout << "\n请输入请求的IP地址:";
	char str[15];
	cin >> str;
	RevIP = ARPFrame.RecvIP = inet_addr(str);
	SendIP = ARPFrame.SendIP = IPPacket->SendIP;//将网卡IP赋值给数据报的源IP
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}

	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "ARP请求发送失败" << endl;
	}
	else
	{
		getip_mac(SendIP, RevIP);
	}
}
int main()
{	
	findalldevc();
	opennetwork();
	filter();
	ARPconsist();
	//将所选择的网卡的IP设置为请求的IP地址
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}
	//使用 pcap_sendpacket 函数发送一个构建好的ARP请求报文
	pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	cout << "ARP请求发送成功" << endl;
	getip_mac(SendIP, RevIP);
	senddata();
} 
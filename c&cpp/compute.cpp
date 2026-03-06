#include<iostream>
#include<stdio.h>
#include<string.h>
#include<thread>
#include<vector>
#include"cipher_h/pbkdf2_hmac.h"
#include"cipher_h/hmac.h"
#include"read.h"
#include"compute.h"

int passwd_number = 0;
char stop = 0;
unsigned char min_Mac[6] = { 0 }, max_Mac[6] = { 0 }, min_Nonce[32] = { 0 }, max_Nonce[32] = { 0 };
unsigned char pmk[32] = { 0 }, ptk_data[100] = { 0 }, ptk[20] = { 0 }, mic[16] = { 0 }, data_mic[33] = {  };
unsigned char label[] = { "Pairwise key expansion" };
char passwd_mark[1] = { 0 };
char passwd_char[5000][63];
char hex_out[512] = { 0 };//测试
//const unsigned char ceshi_ptkdata[1] = { 0x00 };

char* read() {
	if (passwd_number==5001)
	{
		passwd_number = 0;
		read_passwd();
	}
	return passwd_char[passwd_number++];
}
char compare() {
	if (memcmp(mic, data_mic, 16)==0) {
		return passwd_mark[1]='y';
	}
	else {
		return passwd_mark[1]='n';
	}
}
void mac_nonce_compare_create_data(//比较排序，构建ptk输入数据
	unsigned char* anonce,
	unsigned char* snonce,
	unsigned char* amac,
	unsigned char* smac) {
	if (memcmp(amac, smac, 6)<=0)
	{
		memcpy(ptk_data + 23, amac, 6);
		memcpy(ptk_data + 29, smac, 6);
	}
	else
	{
		memcpy(ptk_data + 29, amac, 6);
		memcpy(ptk_data + 23, smac, 6);
	}
	if (memcmp(anonce, snonce, 32) <= 0)
	{
		memcpy(ptk_data + 35, anonce, 32);
		memcpy(ptk_data + 67, snonce, 32);
	}
	else
	{
		memcpy(max_Nonce, anonce, 32);
		memcpy(ptk_data + 67 + 35, snonce, 32);
	}
	memcpy(ptk_data, label, 23);
	
}
void bin2hex(unsigned char* in, char* out) {
	const char hex[] = "0123456789ABCDEF";
	for (int i = 0; i < 32; i++) {
		out[2 * i] = hex[(in[i] >> 4) & 0x0F];  
		out[2 * i + 1] = hex[in[i] & 0x0F];     
	}
	out[32] = '\0'; 
}
void main_compute(unsigned char* passwd,
	int passwd_size,
	unsigned char* ssid,
	int ssid_len,
	unsigned char* ptk_data,
	unsigned char* eapol_data) {
	PKCS5_PBKDF2_HMAC(passwd, passwd_size, ssid, ssid_len, 4096, 32, pmk);
	ptk_data[99] = 0x00;//计数器，只要一遍
	hmac_sha1(pmk, 32, ptk_data, 100, ptk);
	hmac_sha1(ptk, 16, eapol_data, 123, mic);
	//bin2hex(mic, hex_out);
	//printf(hex_out);
}
void compute() {
	unsigned char ssid[] = { };//ssid名称转ASCII后的16进制字节
	unsigned char amac[] = { };//ap的mac地址
	unsigned char smac[] = { };//sta的mac地址
	unsigned char anonce[] =
	{ };//ap的随机数，第一步握手
	unsigned char snonce[] =
	{  };//sta的随机数，第二步握手
	unsigned char eapol_data[] =
	{ };//在802.1X Authentication栏中的数据，mic字段置零
	mac_nonce_compare_create_data(anonce, snonce, amac, smac);//先比较，拼数据
	int ssid_len = sizeof(ssid);//转ssid长度
	int passwd_size = 0;
	read_passwd();
	while (	compare()!='y') {
		char* finish =read() ;
		//printf(read());//测试
		//printf("\n");
		passwd_size = strlen(finish);//密码输入,长度计算
		main_compute((unsigned char*)finish, passwd_size,ssid,ssid_len, ptk_data,eapol_data);//进行主计算
		if (compare() == 'y')
		{
			printf(finish);
			return;
		}
	}
	
}
//void create_thread() {
//	int* a= &passwd_number;
//	read_passwd();
//	//compute();
//	std::vector<std::thread> thread_compute;
//	for (size_t i = 0; i < 16; i++)//16换成处理器数量
//	{
//		thread_compute.emplace_back(compute);
//	}
//	if (stop==1)
//	{
//		for (size_t i = 0; i < 16; i++)//16换成处理器数量
//		{
//			thread_compute[i].join();
//		}
//	}
//}


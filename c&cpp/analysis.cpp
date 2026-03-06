#define _CRT_SECURE_NO_WARNINGS
#include<iostream>
#include<windows.h>
using namespace std;

char filename[100] = {0};
void system_data() {//判断系统硬件配置，便于设置性能
	SYSTEM_INFO cpu_core;//判断cpu核数
	GetSystemInfo(&cpu_core);
	char core;
	core = cpu_core.dwNumberOfProcessors;
	char* p_core = &core;
	FILE* fd;
	fd = fopen(".\\evidence\\data.txt", "a");
	fprintf(fd, "处理器内核数量:%lu\n", cpu_core.dwNumberOfProcessors/2);
	FILE* pipe = _popen("nvidia-smi --query-gpu=name --format=csv,noheader", "r");//判断gpu的cuda数量
	char gpu_name[50];
	fgets(gpu_name, sizeof(gpu_name), pipe);
	_pclose(pipe);
	fputs(gpu_name, fd);
	typedef struct {//定义一个gpu型号和cuda数量的关系结构体
		char gpu_n[50];
		int gpu_cuda_data;
	}gpu_cuda;
	gpu_cuda gpu[]{//要什么型号自己加
		{"NVIDIA GeForce RTX 4060 Laptop GPU\n",
		3072},
	};
	int i = 0;
	int a = 1;
	while (a != 0) {
		a = strcmp(gpu_name, gpu[i].gpu_n);
		if (a == 0)
		{
			fprintf(fd, "cuda数为:");
			fprintf(fd, "%d", gpu[i].gpu_cuda_data);
			fprintf(fd, "\n");
			fclose(fd);
			break;
		}
		i = i + 1;
	}

}
void bin2hex(unsigned char* in, char* out, int len) {//将16进制字节转化为字符
	int a = 0;
	char hex[] = "0123456789ABCDEF";
	len = len * 2;
	for (size_t i = 0; i < len; i = i + 2)
	{
		out[i] = hex[(in[a] >> 4) & 0x0f];
		out[i + 1] = hex[in[a] & 0x0f];
		a++;
	}
	out[len + 1] = '\0';
}
void analysis_datatxt(unsigned char* datain, int len) {//向计算凭据文件中写参数
	FILE* fd;
	fd = fopen(".\\evidence\\data.txt", "a");
	char dataout[1000] = { 0 };
	bin2hex(datain, dataout, len);
	fputs(dataout, fd);
	fputs("\n", fd);
}
void analysis_frame() {
	FILE* fp;
	int offset = 0;
	int readset = 0;
	int frame_length_hex[2] = { 0 };
	int frame_length = 0;
	int type_figure[1] = { 0 };
	char ssid_length[1] = { 0 };
	int order_type[1] = { 0 };
	int step_type[1] = { 0 };
	unsigned char mic_data_len[2] = { 0 };
	int mic_data_len_int = 0;
	int read_ture[1] = { 0 };
	unsigned char ssid[32] = { 0 };
	unsigned char ap_mac[6] = { 0 };
	unsigned char sta_mac[6] = { 0 };
	unsigned char anonce[32] = { 0 };
	unsigned char snonce[32] = { 0 };
	unsigned char mic[16] = { 0 };
	unsigned char mic_data[255] = { 0 };
	char finish[8] = { 0 };//ssid,apmac,stamac,anonce,snonce,mic,micdata完成情况
	fp =fopen(".\\resource\\oneplus2.cap", "rb");//filename
	offset = 24;
	fseek(fp, offset, SEEK_CUR);
	read_ture[0] = 1;//先置1，不然不能跑
	while (read_ture[0] !=0) {//如果下一字节数据为空，则跳出循环
		frame_length_hex[0] = 0;//置零帧长计数二进制数据
		frame_length_hex[1] = 0;//置零帧长计数二进制数据
		frame_length = 0;//置零帧长计数
		offset = 8;
		fseek(fp, offset, SEEK_CUR);
		for (size_t i = 0; i < 2; i++)
		{
			readset = 1;
			fread(frame_length_hex+i, 1, readset, fp);//读取帧长度原始二进制数据
		}
		frame_length = frame_length_hex[1] * 256 + frame_length_hex[0];
		offset = 6;
		fseek(fp, offset, SEEK_CUR);
		finish[7] = finish[0] + finish[1] + finish[2] + finish[3] + finish[4] + finish[5] + finish[6];
		if (finish[7]==7)//判断数据全没全
		{
			FILE* fd;//开始写参数
			fd = fopen(".\\evidence\\data.txt", "a");
			fputs("ssid:", fd);
			fclose(fd);
			analysis_datatxt(ssid, ssid_length[0]);
			fputs("ap mac:", fd);
			fclose(fd);
			analysis_datatxt(ap_mac, 6);
			fputs("sta mac:", fd);
			fclose(fd);
			analysis_datatxt(sta_mac, 6);
			fputs("anonce:", fd);
			fclose(fd);
			analysis_datatxt(anonce, 32);
			fputs("snonce:", fd);
			fclose(fd);
			analysis_datatxt(snonce, 32);
			fputs("mic:", fd);
			fclose(fd);
			analysis_datatxt(mic, 16);
			fputs("mic data:", fd);
			fclose(fd);
			analysis_datatxt(mic_data, mic_data_len_int);
			fclose(fd);
			fclose(fp);
			break;
		}
		readset = 1;
		fread(type_figure, 1, readset, fp);
		if (type_figure[0] == 128) {//ssid的二进制值
			offset = 36;
			readset = 1;
			fseek(fp, offset, SEEK_CUR);
			fread(ssid_length, 1, readset, fp);
			readset = *ssid_length;
			fread(ssid, 1, readset, fp);//ssid二进制名称
			finish[0] = 1;
			offset = frame_length-38-ssid_length[0];
			fseek(fp, offset, SEEK_CUR);
			continue;
		}
		else if (type_figure[0] == 136){//ap,sta的mac值
			offset = 15;
			readset = 6;
			fseek(fp, offset, SEEK_CUR);
			fread(ap_mac, 1, readset, fp);//ap_mac是固定位置
			finish[1] = 1;
			offset = 17;
			readset = 1;
			step_type[0] = 0;
			fseek(fp, offset, SEEK_CUR);
			fread(step_type, 1, readset, fp);
			if (step_type[0]==0)//取anonce
			{
				offset = 11;
				readset = 32;
				fseek(fp, offset, SEEK_CUR);
				fread(anonce, 1, readset, fp);
				finish[3] = 1;
				offset = frame_length - 83;
				fseek(fp, offset, SEEK_CUR);
				continue;
			}
			if (step_type[0] == 1)//取sta_mac,mic_data,mic,snonce
			{
				offset = -30;
				readset = 6;
				fseek(fp, offset, SEEK_CUR);
				fread(sta_mac, 1, readset, fp);
				finish[2] = 1;
				offset = 20;
				fseek(fp, offset, SEEK_CUR);
				mic_data_len[0] = 0;
				for (size_t i = 0; i < 2; i++)
				{
					fread(mic_data_len+i, 1, 1, fp);//取计算mic数据长度
				}
				mic_data_len_int = mic_data_len[0] * 256 + mic_data_len[1];
				readset = mic_data_len_int;
				offset = -4;
				fseek(fp, offset, SEEK_CUR);
				fread(mic_data, 1, readset, fp);//取计算mic数据
				for (size_t i = 0; i < 32; i++)
				{
					snonce[i] = mic_data[i + 17];//snonce从mic_data中拿
					if (i < 16)
					{
						mic[i] = mic_data[i + 81];//mic从mic_data中拿
						mic_data[i + 81] = 0;//mic_data的mic值部分要置0
					}

				}
				finish[4] = 1, finish[5] = 1,finish[6] = 1;
				offset = frame_length - 153;
				fseek(fp, offset, SEEK_CUR);
				continue;
			}
		}
		offset = frame_length-1;
		fseek(fp, offset, SEEK_CUR);
		readset = 1;
		read_ture[0] = fread(read_ture, 1, readset, fp);//读取是否为空
		if (read_ture[0]!=0)
		{
			offset = - 1;
			fseek(fp, offset, SEEK_CUR);
		}
	}
}
void analysis_main() {
	/*cout << "请输入配置文件文件所在位置:";
	cin>> filename;*/
	system_data();
	analysis_frame();

}
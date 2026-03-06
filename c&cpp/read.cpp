#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<string.h>
#include"compute.h"
char data[] = { 0 };
char passwd[5000][63] = { 0 };
FILE* p_read_passwd=fopen(".\\dictionary\\8number.txt", "r");
void read_passwd() {
	/*if (p_read_passwd==NULL)
	{
		printf("×Öµä¶ÁÈ¡Íê³É");
		return NULL;
	}*/
	for (size_t i = 0; i < 5000; i++)
	{
		fgets(passwd[i], 63, p_read_passwd);
		/*p_read_passwd = p_read_passwd + sizeof(passwd);*/
		passwd[i][8] = 0;
	}
	memcpy(passwd_char, passwd, 315000);

	

	//return passwd;//printf(passwd);
}
void read_data() {

}
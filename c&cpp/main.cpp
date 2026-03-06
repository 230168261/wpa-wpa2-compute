#include<iostream>
#include"compute.h"
#include"analysis.h"
#include"gpu_compute.h"
#include"dictionary_make.h"
#include"read.h"
using namespace std;
//目前1000密码需要算13.61秒
//多线程计算部分为单线程，要改，比如再加一个专门申请的函数。
int main() {
    //create_thread();//多线程计算程序
    compute();//主计算程序
    //main_make();
    //analysis_main();
    //read_passwd();
}

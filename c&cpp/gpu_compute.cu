#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>

__global__ void testKernel() {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
}

int gpu_main() {  // 用main函数测试，避免gpu_main可能的调用问题
    testKernel<<<2,3>>>();
    cudaDeviceSynchronize();
    return 0;
}
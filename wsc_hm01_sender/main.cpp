#include <iostream>
#include <string>
#include "winsock2.h"
#include "DES.hpp"
#pragma comment(lib,"Ws2_32.lib")

SOCKET sClient; //全局Socket以避免线程间的参数传递
bool connected; //连接状态

DWORD handleRequest(LPVOID);

int main(){
    vector<datas_64> key(1);
    for (int i = 0; i < 64; i = i + 1) {
        key[0].bits.set(i, rand()%2);
    }

    init_secret_key(key[0]);
    init_K_i(secret_key);

    // 初始化 WSA
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 创建Socket
    sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sClient == INVALID_SOCKET)
    {
        std::cout<<"Socket error!\n";
        return 0;
    }

    // 目标服务端协议，地址和端口信息
    SOCKADDR_IN sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(8000);
    sin.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

    // 连接到服务器
    if (connect(sClient, (SOCKADDR *)(&sin), sizeof(sin)) != 0)
    {
        std::cout<<"Connection error!\n";
        return 0;
    }

    // 创建接收数据线程
    HANDLE recvThread = CreateThread(nullptr, 0, handleRequest, nullptr, 0, nullptr);
    std::cout<<"Connected!\n";

    //发送密钥
    string data = to_string(-1) + "\n" + binary_to_string(key);
    send(sClient, data.c_str(), 1+strlen(data.c_str()), 0);

    // 发送信息
    while (true)
    {
        std::string data;
        getline(std::cin, data);
        if(!connected && data=="quit"){
            CloseHandle(recvThread);
            closesocket(sClient);
            WSACleanup();
            return 0;
        }
        data = "Client:" + data;
        strsize = data.size();

        data = fill(data);
        vector<datas_64> v = string_to_binary(data);
        vector<datas_64> data1 = Encryption(v);
        data = to_string(strsize) + "\n" + binary_to_string(data1);

        const char *sendData;
        sendData = data.c_str();
        send(sClient, sendData, 1+strlen(sendData), 0);
    }

    //关闭线程，socket和WSA
    CloseHandle(recvThread);
    closesocket(sClient);
    WSACleanup();
    return 0;
}

DWORD handleRequest(LPVOID mp){
    char revData[255];
    while (true){
        // 接收数据
        if (recv(sClient, revData, 255, 0) <= 0)
        {
            std::cout<<"Server disconnected! Input \'quit\' to quit.\n";
            connected = false;
            break;
        }
        char *token = strtok(revData, "\n");
        strsize = atoi(token);
        token = strtok(NULL, "\n");
        vector<datas_64> data2 = Decryption(string_to_binary(token));
        std::cout << binary_to_string(data2).substr(0,strsize) <<std::endl;
    }
    return 0;
}
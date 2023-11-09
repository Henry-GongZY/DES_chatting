#include "../include/RSA.h"
#include "../include/DES.hpp"
#include "winsock2.h"
#pragma comment(lib,"Ws2_32.lib")

SOCKET sClient;
UINT64 e,n;
char Data[255];
string DESKEY;

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
    if (sClient == INVALID_SOCKET){
        std::cout<<"Socket error!\n";
        return 0;
    }

    // 目标服务端协议，地址和端口信息
    SOCKADDR_IN sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(8000);
    sin.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

    // 连接到服务器
    if (connect(sClient, (SOCKADDR *)(&sin), sizeof(sin)) != 0){
        std::cout<<"Connection error!\n";
        return 0;
    }
    cout<<"Connected!\n";

    //接受e和n并进行存储
    recv(sClient, Data, 255, 0);
    e = strtol(strtok(Data, " "), nullptr, 10);
    n = strtoull(strtok(nullptr," "), nullptr,10);

    //包装DES密钥并进行加密
    for(int i=0;i<=3;i++){
        DESKEY += " " + to_string(Encry(bit2us(key[0],i),e,n));
    }

    //发送
    send(sClient, DESKEY.c_str(), 1+DESKEY.length(), 0);

    // 创建接收数据线程
    HANDLE recvThread = CreateThread(nullptr, 0, handleRequest, nullptr, 0, nullptr);

    // 发送信息
    while (true)
    {
        std::string data;
        getline(std::cin, data);

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
        if (recv(sClient, revData, 255, 0) <= 0){
            std::cout<<"Server disconnected!";
            break;
        }
        char *token = strtok(revData, "\n");
        strsize = strtol(token,nullptr,10);
        token = strtok(nullptr, "\n");
        vector<datas_64> data2 = Decryption(string_to_binary(token));
        std::cout << binary_to_string(data2).substr(0,strsize) <<std::endl;
    }
    return 0;
}
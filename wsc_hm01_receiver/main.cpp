#include <iostream>
#include <winsock2.h>
#include "DES.hpp"
#pragma comment(lib,"Ws2_32.lib")

SOCKET sListener, sClient;

DWORD handleRequest(LPVOID);
void shut();

int main(){

    //初始化WSA
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);

    //创建socket
    sListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sListener == INVALID_SOCKET) {
        std::cout<<"Socket1 error!\n";
        return 0;
    }

    //服务器协议，IP地址，端口的设置和绑定
    SOCKADDR_IN sin;
    sin.sin_family = AF_INET;//指定地址族为IPv4
    sin.sin_port = htons(8000);//设置监听端口
    sin.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//设置绑定的IP

    if (bind(sListener, (SOCKADDR *)&sin, sizeof(sin)) != 0){
        std::cout<<"Bind1 error!\n";
        return 0 ;
    }

    //监听端口
    if (listen(sListener, 5) != 0){
        std::cout<<"Listener1 error!\n";
        return 0;
    }

    //启动信息接收线程,接受来自对方的聊天内容
    HANDLE recvThread = CreateThread(nullptr, 0, handleRequest, nullptr, 0, nullptr);
    std::cout<<"Waiting for connection...\n";

    //使用主线程进行信息发送
    while (true) {
        std::string data;
        getline(std::cin, data);
        if(data == "__quit"){
            std::cout<<"Server shut down!";
            return 0;
        }
        data = "Server:" + data;
        serverstrsize = data.size();

        data = fill(data);
        vector<datas_64> v = string_to_binary(data);
        vector<datas_64> data1 = Encryption(v);
        data = to_string(serverstrsize) + "\n" + binary_to_string(data1);

        const char *sendData;
        sendData = data.c_str();
        send(sClient, sendData, 1+strlen(sendData), 0);
    }

    //关闭线程，socket和WSA
    CloseHandle(recvThread);
    shut();
    return 0;
}

//接收线程
DWORD handleRequest(LPVOID mp){
    while(true) {
        //阻塞式接受来自用户端的请求
        SOCKADDR_IN Csin;
        int sizeOf = sizeof(Csin);
        sClient = accept(sListener, (SOCKADDR *) &Csin, &sizeOf);
        if (sClient == INVALID_SOCKET) {
            std::cout<<"Client1 Acception failure!\n";
        }
        std::cout<<"Client1 connected!\n";

        //从用户端接收数据
        char revData[255];
        while (true) {
            //接收到的数据长度<=0证明用户退出，否则就输出对方的信息
            if (recv(sClient, revData, 255, 0) <= 0) {
                std::cout<<"Client1 quit！\n";
                break;
            }
            char *token = strtok(revData, "\n");
            serverstrsize = atoi(token);
            token = strtok(NULL, "\n");
            if(serverstrsize == -1){
                vector<datas_64> data2 = string_to_binary(token);
                init_secret_key(data2[0]);
                init_K_i(secret_key);
            }else {
                vector<datas_64> data2 = Decryption(string_to_binary(token));
                std::cout << binary_to_string(data2).substr(0, serverstrsize) << std::endl;
            }
        }
    }
}

void shut(){
    closesocket(sClient);
    closesocket(sListener);
    WSACleanup();
}
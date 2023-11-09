#include "../include/RSA.h"
#include "../include/DES.hpp"
#include "winsock2.h"
#pragma comment(lib,"Ws2_32.lib")

SOCKET sListener, sServer;
UINT64 d,e,n;
string RSAKEY;
u_short DESKEY[4];
char Data[256];

DWORD handleRequest(LPVOID);
void shut();

int main(){
    //��ʼ��WSA
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);

    //����socket
    sListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sListener == INVALID_SOCKET) {
        std::cout<<"Socket1 error!\n";
        return 0;
    }

    //��ʼ��RSA
    RSAinit(d,e,n);

    //������Э�飬IP��ַ���˿ڵ����úͰ�
    SOCKADDR_IN sin;
    sin.sin_family = AF_INET;//ָ����ַ��ΪIPv4
    sin.sin_port = htons(8000);//���ü����˿�
    sin.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//���ð󶨵�IP

    if (bind(sListener, (SOCKADDR *)&sin, sizeof(sin)) != 0){
        std::cout<<"Bind1 error!\n";
        return 0 ;
    }

    //�����˿�
    if (listen(sListener, 1) != 0){
        std::cout<<"Listener1 error!\n";
        return 0;
    }

    //����ʽ���������û��˵�����
    SOCKADDR_IN Csin;
    int sizeOf = sizeof(Csin);
    sServer = accept(sListener, (SOCKADDR *) &Csin, &sizeOf);
    if (sServer == INVALID_SOCKET) {
        std::cout << "Client1 Acception failure!\n";
    }
    cout << "Client1 connected!\n";

    //RSA��װe��n
    RSAKEY = to_string(e) + " " + to_string(n);
    //����
    send(sServer, RSAKEY.c_str(), 1+RSAKEY.length(), 0);
    //����DES��Կ
    recv(sServer, Data, 255, 0);

    //���ܲ���ɳ�ʼ��
    DESKEY[0] = Decry(strtol(strtok(Data," "),nullptr,10),d,n);
    for(int i=1;i<=3;i++){
        DESKEY[i] = (Decry(strtol(strtok(nullptr," "),nullptr,10),d,n));
    }

    auto* KEY = new datas_64;
    memcpy(KEY,DESKEY,4*sizeof(u_short));

    init_secret_key(*KEY);
    init_K_i(secret_key);

    //������Ϣ�����߳�,�������ԶԷ�����������
    HANDLE recvThread = CreateThread(nullptr, 0, handleRequest, nullptr, 0, nullptr);

    //ʹ�����߳̽�����Ϣ����
    while (true) {
        std::string data;
        getline(std::cin, data);
        data = "Server:" + data;
        serverstrsize = data.size();

        data = fill(data);
        vector<datas_64> v = string_to_binary(data);
        vector<datas_64> data1 = Encryption(v);
        data = to_string(serverstrsize) + "\n" + binary_to_string(data1);

        const char *sendData;
        sendData = data.c_str();
        send(sServer, sendData, 1+strlen(sendData), 0);
    }

    //�ر��̣߳�socket��WSA
    CloseHandle(recvThread);
    shut();
    return 0;
}

//�����߳�
DWORD handleRequest(LPVOID mp){
    while(true) {
        //���û��˽�������
        char revData[255];
        while (recv(sServer, revData, 255, 0) <= 0) {//���յ������ݳ���<=0֤���û��˳������������Է�����Ϣif (recv(sServer, revData, 255, 0) <= 0) {
            std::cout << "Client1 quit��\n";
            break;
        }
        char *token = strtok(revData, "\n");
        serverstrsize = strtol(token, nullptr, 10);
        token = strtok(nullptr, "\n");
        vector<datas_64> data2 = Decryption(string_to_binary(token));
        cout << binary_to_string(data2).substr(0, serverstrsize) << endl;
    }
}


void shut(){
    closesocket(sServer);
    closesocket(sListener);
    WSACleanup();
}
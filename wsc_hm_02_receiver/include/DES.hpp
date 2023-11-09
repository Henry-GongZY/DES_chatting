#include "pch.h"
#include "data.hpp"

using namespace std;

typedef struct data64 {
    bitset<64> bits;
}datas_64;

typedef struct data56 {
    bitset<56> bits;
}datas_56;

typedef struct data48 {
    bitset<48> bits;
}datas_48;

typedef struct data32 {
    bitset<32> bits;
}datas_32;

typedef struct data28 {
    bitset<28> bits;
}datas_28;

typedef struct data6 {
    bitset<6> bits;
}datas_6;

typedef struct data4 {
    bitset<4> bits;
}datas_4;

typedef struct data2 {
    bitset<2> bits;
}datas_2;

int strsize, serverstrsize;
datas_48 K_i[16];
datas_64 secret_key;

void init_secret_key(); //��ʼ����Կ
void init_K_i(datas_64 secret_key);//����16������Կki
string fill(string str);  //����8���ֽ�
vector<datas_64> string_to_binary(string str);  //���ַ���ת��Ϊ����������֧�����ģ�
string binary_to_string(vector<datas_64> v);    //����������ת��Ϊ�ַ�����֧�����ģ�
datas_64 IP(datas_64 v); //IP�û�
datas_64 IP_inverse(datas_64 v); //IP�����û�
datas_64 W(datas_64 v);   //W����
datas_64 T_iteration(datas_64 v, datas_48* K);  //16��T����
datas_64 T_iteration_inverse(datas_64 v, datas_48* K);   //16��T�������
datas_32 Feistel(datas_32 R, datas_48 K); //Feistel�ֺ���
datas_48 E_extend(datas_32 v); //E-��չ
datas_32 S_box_change(datas_48 v);
datas_4 find_in_Sbox(int index, datas_6 v);
datas_32 P(datas_32 v); //Feistel�ֺ����е�P�û�

//���ܺͽ���
datas_64 byte_Encryption(datas_64 v);           //64λ�ļ����㷨
datas_64 byte_Decryption(datas_64 v);              //64λ�Ľ����㷨

//�������ݵļ��ܺͽ����㷨��ʵ�����Ƕ������㷨�Ķ��ѭ��
vector<datas_64> Encryption(vector<datas_64> v); 
vector<datas_64> Decryption(vector<datas_64> v);

void init_secret_key(datas_64 key) {   //��ʼ����Կ
    secret_key = key;
}

void init_K_i(datas_64 secret_key) { 
    datas_56 tmp;
    for (int i = 0; i < 56; i++) {
        tmp.bits.set(i, secret_key.bits[PC1_Table[i] - 1]);   //PC-1�û�
    }
    //�ֳ�����
    datas_28 C;
    datas_28 D;
    for (int i = 0; i < 28; i++) {
        C.bits.set(i, tmp.bits[i]);
    }
    for (int i = 28; i < 56; i++) {
        D.bits.set(i - 28, tmp.bits[i]);
    }
    //��λ����ֻ��1��2��9��16����һλ�������������λ
    for (int i = 1; i <= 16; i++) {
        if (i == 1 || i == 2 || i == 9 || i == 16) {
            C.bits = C.bits << 1;
            D.bits = D.bits << 1;
        } else {
            C.bits = C.bits << 2;
            D.bits = D.bits << 2;
        }
        //ÿ�������λ�󱣴�
        for (int t = 0; t < 28; t++) {
            tmp.bits.set(t, C.bits[t]);
            tmp.bits.set(t + 28, D.bits[t]);
        }
        //����PC-2�û���������Կ
        for (int t = 0; t < 48; t++) {
            K_i[i - 1].bits.set(t, tmp.bits[PC2_Table[t] - 1]); //PC-2�û�
        }
    }
}

string fill(string str) {     //������8λ��������
    int num = 8 - str.size() % 8;
    for (int i = 0; i < num; i++) {
        str += num;
    }
    return str;
}

vector<datas_64> string_to_binary(string str) {
    vector<datas_64> Plaintext_binary;
    int num = (str.size()+7) / 8;  //��8��byte����
    for (int i = 0; i < num; i++) { //��num��64λ����8��byte/char���ͣ�һ��forѭ����ֵһ��64λbitset
        datas_64 tmp;
        for (int j = 0; j < 8; j++) {  //һ��forѭ����ֵ8λ����һ���ַ�
            int ascii = str.at(8 * i + j);
            bitset<8> a(ascii);   //char(Ҳ����int)תΪbitset
            for (int t = 0; t < 8; t++) {
                tmp.bits.set(j * 8 + t, a[t]);
            }
        }
        Plaintext_binary.push_back(tmp);
    }
    return Plaintext_binary;
}

string binary_to_string(vector<datas_64> v) {
    string str;
    for (int i = 0; i < v.size(); i++) { //ÿ��ѭ������8byte��8���ַ�
        for (int j = 0; j < 8; j++) {  //ÿ��ѭ������1���ַ�
            bitset<8>a;
            for (int t = 0; t < 8; t++) {   //1���ַ�8��bit
                a.set(t, v.at(i).bits[j * 8 + t]);
            }
            str += (int)(a.to_ulong()); //bitsetת��Ϊchar�ټ���string����
        }
    }
    return str;
}

datas_64 IP(datas_64 v) {
    datas_64 data;
    for (int i = 0; i < 64; i++) {
        data.bits.set(i, v.bits[IP_Table[i] - 1]); //IP�û�
    }
    return data;
}

datas_64 IP_inverse(datas_64 v) {
    datas_64 data;
    for (int i = 0; i < 64; i++) {
        data.bits.set(i, v.bits[IP_inverse_Table[i] - 1]); //��IP�û�
    }
    return data;
}

datas_64 W(datas_64 v) {    //ǰ32bits�ͺ�32bits����
    datas_64 data;
    for (int i = 0; i < 32; i++) {
        data.bits.set(i, v.bits[i + 32]);
        data.bits.set(i + 32, v.bits[i]);
    }
    return data;
}

datas_48 E_extend(datas_32 v) {   //E��չ
    datas_48 data;
    for (int i = 0; i < 48; i++) {
        data.bits.set(i, v.bits[E_Table[i] - 1]);
    }
    return data;
}

datas_4 find_in_Sbox(int index, datas_6 v) { //��S����ȡ��
    datas_2 v2;
    datas_4 v4;
    //�ó���һλ�����һλ�����
    //�м���λ�����
    v2.bits.set(0, v.bits[0]);
    v2.bits.set(1, v.bits[5]);
    for (int i = 0; i < 4; i++) {
        v4.bits.set(i, v.bits[i + 1]);
    }
    int row = v2.bits.to_ulong();
    int col = v4.bits.to_ulong();
    int num = S_Box[index][row][col];
    bitset<4>a(num);
    for (int i = 0; i < 4; i++) {
        v4.bits.set(i, a[i]);
    }
    return v4;
}

datas_32 S_box_change(datas_48 v) {
    datas_32 tmp;
    datas_6 data_6[8];
    datas_4 data_4[8];

    for (int i = 0; i < 48; i++) {   //��48λ�����з�
        data_6[(int)(i / 6)].bits.set(i % 6, v.bits[i]);
    }
    for (int i = 0; i < 8; i++) {    //�ҵ�S���ж�Ӧ�����ݣ�����������data_4
        data_4[i] = find_in_Sbox(i, data_6[i]);
    }
    for (int i = 0; i < 32; i++) {   //�ϲ�8��data_4��һ��data_32
        tmp.bits.set(i, data_4[(int)(i / 4)].bits[i % 4]);
    }

    return tmp;
}

//Feistel�ֺ���
datas_32 Feistel(datas_32 R, datas_48 K) {
    datas_48 data = E_extend(R);
    data.bits = (data.bits ^= K.bits);
    datas_32 data_32 = S_box_change(data);
    data_32 = P(data_32);
    return data_32;
}

//Feistel�ֺ����е�P�û�
datas_32 P(datas_32 v) {
    datas_32 data;
    for (int i = 0; i < 32; i++) {
        data.bits.set(i, v.bits[P_Table[i] - 1]);
    }
    return data;
}

//16��T����
datas_64 T_iteration(datas_64 v, datas_48* K) {
    datas_64 data;
    datas_32 L, R;
    for (int i = 0; i < 32; i++) {  //�з�
        L.bits.set(i, v.bits[i]);
        R.bits.set(i, v.bits[i + 32]);
    }
    for (int i = 0; i < 16; i++) {  //16�ε���
        datas_32 L_temp = L;
        datas_32 R_temp = R;
        L = R_temp;
        R.bits = (L_temp.bits ^= Feistel(R_temp, K[i]).bits);
    }
    for (int i = 0; i < 32; i++) {  //�ϲ�
        data.bits.set(i, L.bits[i]);
        data.bits.set(i + 32, R.bits[i]);
    }
    return W(data);
}

//16��T�������
datas_64 T_iteration_inverse(datas_64 v, datas_48* K) {
    datas_64 data;
    datas_32 L, R;
    for (int i = 0; i < 32; i++) {  //�з�
        L.bits.set(i, v.bits[i]);
        R.bits.set(i, v.bits[i + 32]);
    }
    for (int i = 0; i < 16; i++) {  //16�ε���
        datas_32 L_temp = L;
        datas_32 R_temp = R;
        L = R_temp;
        R.bits = (L_temp.bits ^= Feistel(R_temp, K[15 - i]).bits);
    }
    for (int i = 0; i < 32; i++) {  //�ϲ�
        data.bits.set(i, L.bits[i]);
        data.bits.set(i + 32, R.bits[i]);
    }
    return W(data);
}

//64λ�ļ����㷨
datas_64 byte_Encryption(datas_64 v) {
    datas_64 data;
    data = IP(v);
    data = T_iteration(data, K_i);
    data = IP_inverse(data);
    return data;
}

//64λ�Ľ����㷨
datas_64 byte_Decryption(datas_64 v) {
    datas_64 data;
    data = IP(v);
    data = T_iteration_inverse(data, K_i);
    data = IP_inverse(data);
    return data;
}

//�������ݵļ����㷨���ڶ�������Ϊ��Կ
vector<datas_64> Encryption(vector<datas_64> v) {
    vector<datas_64> data;
    for (int i = 0; i < v.size(); i++) {
        data.push_back(byte_Encryption(v.at(i)));
    }
    return data;
}

//�������ݵĽ����㷨���ڶ�������Ϊ��Կ
vector<datas_64> Decryption(vector<datas_64> v) {
    vector<datas_64> data;
    for (int i = 0; i < v.size(); i++) {
        data.push_back(byte_Decryption(v.at(i)));
    }
    return data;
}
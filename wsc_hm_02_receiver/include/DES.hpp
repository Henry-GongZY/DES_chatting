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

void init_secret_key(); //初始化密钥
void init_K_i(datas_64 secret_key);//生成16个子密钥ki
string fill(string str);  //补齐8个字节
vector<datas_64> string_to_binary(string str);  //将字符串转化为二进制数（支持中文）
string binary_to_string(vector<datas_64> v);    //将二进制数转化为字符串（支持中文）
datas_64 IP(datas_64 v); //IP置换
datas_64 IP_inverse(datas_64 v); //IP的逆置换
datas_64 W(datas_64 v);   //W操作
datas_64 T_iteration(datas_64 v, datas_48* K);  //16次T迭代
datas_64 T_iteration_inverse(datas_64 v, datas_48* K);   //16次T的逆迭代
datas_32 Feistel(datas_32 R, datas_48 K); //Feistel轮函数
datas_48 E_extend(datas_32 v); //E-扩展
datas_32 S_box_change(datas_48 v);
datas_4 find_in_Sbox(int index, datas_6 v);
datas_32 P(datas_32 v); //Feistel轮函数中的P置换

//加密和解密
datas_64 byte_Encryption(datas_64 v);           //64位的加密算法
datas_64 byte_Decryption(datas_64 v);              //64位的解密算法

//所有数据的加密和解密算法，实质上是对上面算法的多次循环
vector<datas_64> Encryption(vector<datas_64> v); 
vector<datas_64> Decryption(vector<datas_64> v);

void init_secret_key(datas_64 key) {   //初始化密钥
    secret_key = key;
}

void init_K_i(datas_64 secret_key) { 
    datas_56 tmp;
    for (int i = 0; i < 56; i++) {
        tmp.bits.set(i, secret_key.bits[PC1_Table[i] - 1]);   //PC-1置换
    }
    //分成两半
    datas_28 C;
    datas_28 D;
    for (int i = 0; i < 28; i++) {
        C.bits.set(i, tmp.bits[i]);
    }
    for (int i = 28; i < 56; i++) {
        D.bits.set(i - 28, tmp.bits[i]);
    }
    //移位处理，只有1、2、9、16左移一位，其余均左移两位
    for (int i = 1; i <= 16; i++) {
        if (i == 1 || i == 2 || i == 9 || i == 16) {
            C.bits = C.bits << 1;
            D.bits = D.bits << 1;
        } else {
            C.bits = C.bits << 2;
            D.bits = D.bits << 2;
        }
        //每次完成移位后保存
        for (int t = 0; t < 28; t++) {
            tmp.bits.set(t, C.bits[t]);
            tmp.bits.set(t + 28, D.bits[t]);
        }
        //进行PC-2置换，生成密钥
        for (int t = 0; t < 48; t++) {
            K_i[i - 1].bits.set(t, tmp.bits[PC2_Table[t] - 1]); //PC-2置换
        }
    }
}

string fill(string str) {     //补足至8位的整数倍
    int num = 8 - str.size() % 8;
    for (int i = 0; i < num; i++) {
        str += num;
    }
    return str;
}

vector<datas_64> string_to_binary(string str) {
    vector<datas_64> Plaintext_binary;
    int num = (str.size()+7) / 8;  //以8个byte分组
    for (int i = 0; i < num; i++) { //有num个64位，即8个byte/char类型，一个for循环赋值一个64位bitset
        datas_64 tmp;
        for (int j = 0; j < 8; j++) {  //一个for循环赋值8位，即一个字符
            int ascii = str.at(8 * i + j);
            bitset<8> a(ascii);   //char(也就是int)转为bitset
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
    for (int i = 0; i < v.size(); i++) { //每个循环翻译8byte即8个字符
        for (int j = 0; j < 8; j++) {  //每个循环翻译1个字符
            bitset<8>a;
            for (int t = 0; t < 8; t++) {   //1个字符8个bit
                a.set(t, v.at(i).bits[j * 8 + t]);
            }
            str += (int)(a.to_ulong()); //bitset转换为char再加入string后面
        }
    }
    return str;
}

datas_64 IP(datas_64 v) {
    datas_64 data;
    for (int i = 0; i < 64; i++) {
        data.bits.set(i, v.bits[IP_Table[i] - 1]); //IP置换
    }
    return data;
}

datas_64 IP_inverse(datas_64 v) {
    datas_64 data;
    for (int i = 0; i < 64; i++) {
        data.bits.set(i, v.bits[IP_inverse_Table[i] - 1]); //逆IP置换
    }
    return data;
}

datas_64 W(datas_64 v) {    //前32bits和后32bits交换
    datas_64 data;
    for (int i = 0; i < 32; i++) {
        data.bits.set(i, v.bits[i + 32]);
        data.bits.set(i + 32, v.bits[i]);
    }
    return data;
}

datas_48 E_extend(datas_32 v) {   //E扩展
    datas_48 data;
    for (int i = 0; i < 48; i++) {
        data.bits.set(i, v.bits[E_Table[i] - 1]);
    }
    return data;
}

datas_4 find_in_Sbox(int index, datas_6 v) { //从S盒中取数
    datas_2 v2;
    datas_4 v4;
    //拿出第一位和最后一位组成行
    //中间四位组成列
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

    for (int i = 0; i < 48; i++) {   //将48位均匀切分
        data_6[(int)(i / 6)].bits.set(i % 6, v.bits[i]);
    }
    for (int i = 0; i < 8; i++) {    //找到S盒中对应的数据，并将其置于data_4
        data_4[i] = find_in_Sbox(i, data_6[i]);
    }
    for (int i = 0; i < 32; i++) {   //合并8个data_4成一个data_32
        tmp.bits.set(i, data_4[(int)(i / 4)].bits[i % 4]);
    }

    return tmp;
}

//Feistel轮函数
datas_32 Feistel(datas_32 R, datas_48 K) {
    datas_48 data = E_extend(R);
    data.bits = (data.bits ^= K.bits);
    datas_32 data_32 = S_box_change(data);
    data_32 = P(data_32);
    return data_32;
}

//Feistel轮函数中的P置换
datas_32 P(datas_32 v) {
    datas_32 data;
    for (int i = 0; i < 32; i++) {
        data.bits.set(i, v.bits[P_Table[i] - 1]);
    }
    return data;
}

//16次T迭代
datas_64 T_iteration(datas_64 v, datas_48* K) {
    datas_64 data;
    datas_32 L, R;
    for (int i = 0; i < 32; i++) {  //切分
        L.bits.set(i, v.bits[i]);
        R.bits.set(i, v.bits[i + 32]);
    }
    for (int i = 0; i < 16; i++) {  //16次迭代
        datas_32 L_temp = L;
        datas_32 R_temp = R;
        L = R_temp;
        R.bits = (L_temp.bits ^= Feistel(R_temp, K[i]).bits);
    }
    for (int i = 0; i < 32; i++) {  //合并
        data.bits.set(i, L.bits[i]);
        data.bits.set(i + 32, R.bits[i]);
    }
    return W(data);
}

//16次T的逆迭代
datas_64 T_iteration_inverse(datas_64 v, datas_48* K) {
    datas_64 data;
    datas_32 L, R;
    for (int i = 0; i < 32; i++) {  //切分
        L.bits.set(i, v.bits[i]);
        R.bits.set(i, v.bits[i + 32]);
    }
    for (int i = 0; i < 16; i++) {  //16次迭代
        datas_32 L_temp = L;
        datas_32 R_temp = R;
        L = R_temp;
        R.bits = (L_temp.bits ^= Feistel(R_temp, K[15 - i]).bits);
    }
    for (int i = 0; i < 32; i++) {  //合并
        data.bits.set(i, L.bits[i]);
        data.bits.set(i + 32, R.bits[i]);
    }
    return W(data);
}

//64位的加密算法
datas_64 byte_Encryption(datas_64 v) {
    datas_64 data;
    data = IP(v);
    data = T_iteration(data, K_i);
    data = IP_inverse(data);
    return data;
}

//64位的解密算法
datas_64 byte_Decryption(datas_64 v) {
    datas_64 data;
    data = IP(v);
    data = T_iteration_inverse(data, K_i);
    data = IP_inverse(data);
    return data;
}

//所有数据的加密算法，第二个参数为密钥
vector<datas_64> Encryption(vector<datas_64> v) {
    vector<datas_64> data;
    for (int i = 0; i < v.size(); i++) {
        data.push_back(byte_Encryption(v.at(i)));
    }
    return data;
}

//所有数据的解密算法，第二个参数为密钥
vector<datas_64> Decryption(vector<datas_64> v) {
    vector<datas_64> data;
    for (int i = 0; i < v.size(); i++) {
        data.push_back(byte_Decryption(v.at(i)));
    }
    return data;
}
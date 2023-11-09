//
// Created by lxdzh on 2021/4/29.
//

#ifndef WSC_HM_02_RECEIVER_RSA_H
#define WSC_HM_02_RECEIVER_RSA_H

#include "pch.h"

using namespace std;

inline unsigned __int64 MulMod(unsigned __int64 a, unsigned __int64 b, unsigned __int64 n){
    return (a * b) % n;
}

unsigned __int64 PowMod(unsigned __int64 base, unsigned __int64 pow, unsigned __int64 n){
    unsigned __int64 a=base, b=pow, c=1;
    while(b){
        while(!(b & 1)){
            b>>=1;
            a=MulMod(a, a, n);
        }
        b--;
        c=MulMod(a, c, n);
    }
    return c;
}

long RabinMillerKnl(unsigned __int64 &n){
    unsigned __int64 a, q, k, v;
    default_random_engine engine(time(nullptr));
    q=n - 1;
    k=0;
    while(!(q & 1)){
        ++k;
        q>>=1;
    }
    uniform_int_distribution<unsigned>u(0,n-3);
    a=2 + u(engine);
    v=PowMod(a, q, n);
    if(v == 1){
        return 1;
    }
    for(int j=0;j<k;j++){
        unsigned int z=1;
        for(int w=0;w<j;w++){
            z*=2;
        }
        if(PowMod(a, z*q, n)==n-1)
            return 1;
    }
    return 0;
}

long RabinMiller(unsigned __int64 &n, long loop=100){
    for(long i=0; i < loop; i++){
        if(!RabinMillerKnl(n))
            return 0;
    }
    return 1;
}

unsigned __int64 RandomPrime(char bits){
    unsigned __int64 base;
    do{
        base= (unsigned long)1 << (bits - 1); //保证最高位是1
        uniform_int_distribution<unsigned>u(0,base);
        base+=rand()%base; //再加上一个随机数
        base|=1; //保证最低位是1,即保证是奇数
    } while(!RabinMiller(base, 30)); //进行拉宾－米勒测试30 次
    return base; //全部通过认为是质数
}

unsigned __int64 Gcd(unsigned __int64 &p, unsigned __int64 &q)
{
    unsigned __int64 a=p > q ? p : q;
    unsigned __int64 b=p < q ? p : q;
    unsigned __int64 t;
    if(p == q){
        return p; //两数相等,最大公约数就是本身
    } else{
        while(b) {//辗转相除法,gcd(a,b)=gcd(b,a-qb)
            a=a % b;
            t=a;
            a=b;
            b=t;
        }
        return a;
    }
}

unsigned __int64 Euclid(unsigned __int64 e, unsigned __int64 t_n)
{
    unsigned __int64 Max=0xffffffffffffffff-t_n;
    unsigned __int64 i=1;
    while(true){
        if(((i*t_n)+1)%e==0){
            return ((i*t_n)+1)/e;
        }
        i++;
        unsigned __int64 Tmp=(i+1)*t_n;
        if(Tmp>Max) {
            return 0;
        }
    }
    return 0;
}

static unsigned __int64 Encry(unsigned short nSorce, unsigned __int64 e, unsigned __int64 n){
    return PowMod(nSorce, e, n);
}

unsigned short Decry(unsigned __int64 nSorce, unsigned __int64 d, unsigned __int64 n)
{
    unsigned __int64 nRes = PowMod(nSorce, d, n);
    auto * pRes=(unsigned short*)&(nRes);
    if(pRes[1]!=0||pRes[3]!=0||pRes[2]!=0) {
        return 0;
    } else{
        return pRes[0];
    }
}

void RSAinit(unsigned __int64 &d,unsigned __int64 &e,unsigned __int64 &n){
    unsigned __int64 s,t;
    default_random_engine engine(time(nullptr));
    uniform_int_distribution<unsigned __int64>u(0,65536);
    unsigned __int64 p = RandomPrime(16);
    unsigned __int64 q = RandomPrime(16);
    n = p * q;
    unsigned __int64 f = (p - 1) * (q - 1);
    do
    {
        e=u(engine);
        e|=1;
    } while(Gcd(e, f) != 1);
    d = Euclid(e,f);
    s = 0;
    t=n >> 1;
    while(t) {
        s++;
        t>>=1;
    }
}

#endif //WSC_HM_02_RECEIVER_RSA_H

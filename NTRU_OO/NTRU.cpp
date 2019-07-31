#ifndef NTRU_H
#define NTRU_H
#include "NTRU.hpp"
#endif

ZZ_pX NTRU::setmodulo(ZZX &a, ZZ& p, long n){
    ZZ_p::init(p);

    ZZ_pX v;
    v.SetLength(n);
    for(long i = 0; i < n; i++)
        v[i] = to_ZZ_p(a[i]);

    return v;
}

void NTRU::zerocenter(ZZX &a, ZZ& p, long n){
    for(long i = 0; i < n; i++)    {
        if(a[i] > (p-1)/2)
            a[i] = a[i]-p;
    }
      return;
}

ZZX NTRU::removemodulo(ZZ_pX &a, long n){
    ZZX v;
    ZZ_p r;

    v.SetLength(n);
    for(long i = 0; i < n; i++)    {
        r = coeff(a,i);
        v[i] = rep(r);
    }
    return v;
}

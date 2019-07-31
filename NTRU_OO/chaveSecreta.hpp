#include <NTL/ZZ.h> 
#include <NTL/ZZX.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZXFactoring.h>
#include <iostream>
#include <stdlib.h>     
#include <time.h> 
#include <fstream>
#include <sstream>
NTL_CLIENT;
#ifndef NTRU_H
#define NTRU_H
#include "NTRU.hpp"
#endif
class chaveSecreta:public NTRU{

    public:
        
        ZZ_pX f1,fx,R_new,h,e,phx_new,g_new,r_new,m_new,ax,f2,bx;
        ZZX phx;    
        int cont0=0,cont1=0,moeda;
        ofstream certificado;
        chaveSecreta(){
            
        };
        ZZ_pX gera_chave_publica(ZZX m);
        ZZ_pX decripta(ZZ_pX a, ZZX R, ZZ q, ZZ p, ZZX f ,long N);
};
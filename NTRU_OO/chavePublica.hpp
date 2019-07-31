#include <NTL/ZZ.h> 
#include <NTL/ZZX.h>
#include <NTL/ZZXFactoring.h>
#include <NTL/ZZ_pX.h>
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
class chavePublica:public NTRU{
        
public:  
    chavePublica(){
        
    };
    ZZ_pX e, ax;
    ZZ_pX encripta(ZZ_pX h, ZZ_pX phx_new, ZZ_pX R_new, ZZ_pX r_new, ZZ_pX m_new, ZZ_pX fx);

    
};
#include <NTL/ZZ.h> 
#include <NTL/ZZX.h>
#include <NTL/ZZXFactoring.h>
#include <iostream>
#include <stdlib.h>     
#include <time.h> 
#include <fstream>
#include <sstream>
NTL_CLIENT;

class NTRU{
    
    public:
        long  N,n,d,p;
        ZZ q; 
        ZZX f,g,f1,R,s,t,x,h,r,p_x,f2,f_aux,aux,m,bm,a_null_modulo,a_aux;
        ZZ_pX a,b,a_zero,m_final;
        ZZ_pX setmodulo(ZZX &a, ZZ& p, long n);

        void zerocenter(ZZX &a, ZZ& p, long n);
        static bool seeded;
        ZZX removemodulo(ZZ_pX &a, long n);
        
        NTRU(){
            p = 3;   
            N = 743;
            if(!seeded){
                srand (time(NULL));
                seeded = true;
            }
            
        }
};

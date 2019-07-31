#include <NTL/ZZ.h> 
#include <NTL/ZZX.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZXFactoring.h>
#include <iostream>
#include <stdlib.h>     
#include <time.h> 
#include <fstream>
#include <sstream>
#include <string.h>
NTL_CLIENT;
#include "chaveSecreta.hpp"
#include "chavePublica.hpp"

bool NTRU::seeded = false;

int main(int argc, char  *argv[]){	

    NTRU::seeded = false;
    ZZX bm, texto_decifrado;
    ZZ_pX h,texto_cifrado,texto;
    char mensagem [49];    
    NTRU *ntru = new NTRU();
    chaveSecreta *chaveS = new chaveSecreta();
    chavePublica *chaveP = new chavePublica();
    strcpy(mensagem, argv[2]);
    
    
    //Mensagem
	int i=0,x;
   
	ntru->m.SetLength(ntru->N);	
    
	while (i<48){
        x = int(mensagem[i]);        
		ntru->m[i] = ZZ(x);
		i++;
	}
    ntru->m[ntru->N-1]=ZZ(48);
    cout << ntru->m << endl;
	int opcao = atoi(argv[4]);
    switch (opcao){
        case 1:
            chaveS->gera_chave_publica(ntru->m);             
        break;

        case 2:            
             //chaveP->encripta(h, chaveS->phx_new, chaveS->R_new, chaveS->r_new, chaveS->m_new, chaveS->fx);
        break;

        case 3 :
            /* texto = chaveS->decripta(m,R,q,ZZ(3),f,743);
            texto_decifrado = ntru->removemodulo(texto,743);
	        ntru->zerocenter(*texto_decifrado,3,743); */

        break;

        default :
            printf ("Opção invalida !");
       
            
    }
	

    
    
    
	
	
    
    
    	
	
	
	
	
	
	
	cout <<"M_plain "<< bm << endl;


	return 0;
}
#include "chavePublica.hpp"
ZZ_pX chavePublica::encripta(ZZ_pX h, ZZ_pX phx_new, ZZ_pX R_new, ZZ_pX r_new, ZZ_pX m_new, ZZ_pX fx){

    MulMod(e,phx_new,h,R_new);
	MulMod(e,e,r_new,R_new);
	add(e,e,m_new);	
	MulMod(ax,fx,e,R_new);
    a_null_modulo= removemodulo(ax,N);
	zerocenter(a_null_modulo,q,N);
	a_zero=setmodulo(a_null_modulo,p,N);

    return a_zero;
	
}
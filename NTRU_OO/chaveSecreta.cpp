#include "chaveSecreta.hpp"

ZZ_pX chaveSecreta::gera_chave_publica(ZZX m){
	
    N = 743;	
	p = 3;		
	d = 1 + RandomBnd(N/2);		
	q = (6*d+1)*p + 256;
	q = NextPrime(q, 30); 
	certificado.open("certificado.txt");		
	R.SetLength(N+1);	
	R[0]=-1;
	R[N]=1;	
	f.SetLength(N);
	
	//F(x)
	while(cont0<d+1){
		moeda = rand()%N;
		
		if(f[moeda]==0){
			f[moeda]=1;
			cont0++;			
		}
	}
	while(cont1<d){
		moeda = rand()%N;
		if(f[moeda]==0){
			f[moeda]=-1;
			cont1++;
		}
	}
	
	//G(x)
	cont0=0;
	g.SetLength(N);
	
  while(cont0<d){
		moeda = rand()%N;
		if(g[moeda]==0){
			g[moeda]=-1;
			cont0++;
		}
	}
    
	cont1=0;
  	while(cont1<d){
		moeda = rand()%N;
		if(g[moeda]==0){
			g[moeda]=1;
			cont1++;
		}
	}
	
	
	//r(x)
	cont0=0;
	r.SetLength(N);

  	while(cont0<d){
		moeda = rand()%N;
		if(r[moeda]==0){
			r[moeda]=-1;
			cont0++;
		}
	}
	cont1=0;
  	while(cont1<d){
		moeda = rand()%N;
		if(r[moeda]==0){
			r[moeda]=1;
			cont1++;
		}
	}
	
    
    
    ZZ_p::init(to_ZZ(q));

	phx.SetLength(1);
	R_new.SetLength(N+1);
	f1.SetLength(N);
	h.SetLength(N);
	e.SetLength(N);
	ax.SetLength(N);
	
	
	phx[0]=p;

	zerocenter(g,q,N);	
	zerocenter(r,q,N);	
	zerocenter(m,q,N);
		
	g_new = setmodulo(g,q,N);
	phx_new = setmodulo(phx,q,1);
	r_new = setmodulo(r,q,N);
	R_new = setmodulo(R,q,N+1); 
	m_new = setmodulo(m,q,N);
	zerocenter(f,q,N);
	
	fx = setmodulo(f,q,N);		
	InvMod(f1, fx, R_new);	
	MulMod(h,f1,g_new,R_new);
	
	/* PARAMETROS PUBLICOS */
    certificado << N << endl;
	certificado << p << endl;
	certificado << q << endl;
	certificado << d << endl;

	/* PARAMETROS ENCRIPTAR */
	certificado << h << endl;
	certificado << phx_new << endl;	
	certificado << R_new << endl;	
	certificado << r_new << endl;
	certificado << m_new << endl;
	certificado << fx << endl;
	

	/* PARAMETROS DECRIPTAR */
	certificado << f << endl;
	certificado << R << endl;
    


	return h;

}

ZZ_pX chaveSecreta::decripta(ZZ_pX a, ZZX R, ZZ q, ZZ p, ZZX f ,long N){	
	
	ZZ_p::init(to_ZZ(p));

	R_new.SetLength(N+1);
	R_new = setmodulo(R,p,N+1);

	zerocenter(f,p,N);
	fx = setmodulo(f,p,N);

	InvMod(f2,fx, R_new);	
	MulMod(bx,a,f2,R_new);	
	
	
	return bx;
}
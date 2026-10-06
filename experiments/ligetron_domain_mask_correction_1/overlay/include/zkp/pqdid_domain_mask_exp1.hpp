// Experimental CPU component and explicitly labelled transform model.
#pragma once
#include <zkp/finite_field_gmp.hpp>
#include <vector>
#include <stdexcept>
#include <algorithm>
namespace ligero::vm::zkp::dm1 {
using F = bn254_gmp;
using V = std::vector<mpz_class>;
inline mpz_class mod(const mpz_class& a) { mpz_class r; F::reduce(r,a); return r; }
inline mpz_class mul(const mpz_class& a,const mpz_class& b) { mpz_class r; F::mulmod(r,a,b);return r; }
inline mpz_class power(const mpz_class& a, unsigned long n) { mpz_class r; mpz_powm_ui(r.get_mpz_t(),a.get_mpz_t(),n,F::modulus.get_mpz_t());return r; }
inline mpz_class inv(const mpz_class& a) { if(a==0) throw std::invalid_argument("zero inverse");mpz_class r;F::invmod(r,a);return r; }
inline void canonical(const V& a) {for(const auto& x:a) if(x<0 || x>=F::modulus)throw std::invalid_argument("noncanonical field value");}
inline void dimensions(size_t k,size_t ell,size_t t) {
 if(k<4 || k>8192 || (k&(k-1)) || ell==0 || ell>=k || t>=k-ell)throw std::invalid_argument("dimensions/padding");
}
inline void fixed_profile(size_t k,size_t ell,size_t n,size_t t) {
 if(k!=8192 || ell!=7936 || n!=32768 || t!=192)throw std::invalid_argument("experimental profile mismatch");
}
inline void transform(V& a,mpz_class root,bool inverse=false) {
 canonical(a);const size_t n=a.size();if(n==0 || (n&(n-1)))throw std::invalid_argument("NTT length");
 if(power(root,n)!=1 || (n>1 && power(root,n/2)==1))throw std::invalid_argument("root order");
 if(inverse)root=inv(root);
 for(size_t i=1,j=0;i<n;++i){size_t b=n>>1;for(;j&b;b>>=1)j^=b;j^=b;if(i<j)std::swap(a[i],a[j]);}
 for(size_t len=2;len<=n;len<<=1){mpz_class step=power(root,n/len);for(size_t i=0;i<n;i+=len){mpz_class w=1;for(size_t j=0;j<len/2;++j){mpz_class x=a[i+j], y=mul(a[i+j+len/2],w);a[i+j]=mod(x+y);a[i+j+len/2]=mod(x-y);w=mul(w,step);}}}
 if(inverse){mpz_class ni=inv(mpz_class(n));for(auto& x:a)x=mul(x,ni);}
}
inline V encode(V a,size_t n,mpz_class interpolation_root,mpz_class code_root,mpz_class delta=7){
 if(n<a.size() || delta==0 || power(delta,n)==1)throw std::invalid_argument("overlapping coset");
 transform(a,interpolation_root,true);a.resize(n);mpz_class d=1;for(auto& x:a){x=mul(x,d);d=mul(d,delta);}transform(a,code_root);return a;
}
inline V coefficients(V a,mpz_class code_root,mpz_class delta=7){
 if(delta==0 || power(delta,a.size())==1)throw std::invalid_argument("overlapping coset");
 transform(a,code_root,true);mpz_class di=inv(delta),d=1;for(auto& x:a){x=mul(x,d);d=mul(d,di);}return a;
}
inline V decode(V a,size_t k,mpz_class root,mpz_class code_root,size_t degree){
 a=coefficients(a,code_root);if(degree>a.size())throw std::invalid_argument("degree");
 for(size_t j=degree;j<a.size();++j)if(a[j]!=0)throw std::invalid_argument("degree overflow");
 V out(k);for(size_t j=0;j<degree;++j)out[j%k]=mod(out[j%k]+a[j]);transform(out,root);return out;
}
template<class Draw> inline std::array<V,3> masks(size_t k,size_t ell,Draw draw){
 dimensions(k,ell,0);auto [wk,w2,wn]=F::generate_omegas(k,4*k);(void)wk;(void)wn;
 std::array<V,3> out{V(k),V(2*k),V(2*k)};
 for(auto& x:out[0])x=draw();
 // Uniform coefficient vector, projected onto the one sum-zero constraint.
 for(size_t i=0;i<2*k-1;++i)out[1][i]=draw();
 transform(out[1],w2);mpz_class sum=0;for(size_t i=0;i<ell;++i)sum=mod(sum+out[1][2*i]);
 mpz_class mean=mul(sum,inv(mpz_class(ell)));for(auto& x:out[1])x=mod(x-mean);
 // Evaluations with required zeros; one public pivot removes the top coefficient.
 mpz_class weighted=0,w=1;
 for(size_t i=0;i<2*k-1;++i){if(i%2 || i/2>=ell)out[2][i]=draw();weighted=mod(weighted+mul(out[2][i],w));w=mul(w,w2);}
 out[2].back()=mod(-mul(weighted,inv(w)));return out;
}
} // namespace ligero::vm::zkp::dm1

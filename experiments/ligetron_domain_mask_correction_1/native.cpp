#include <util/mpz_assign.hpp>
#include <zkp/backend/witness_manager.hpp>
#include <zkp/pqdid_rng_exp1.hpp>
#include <sstream>
using namespace ligero::vm;
using namespace ligero::vm::zkp;
using namespace ligero::vm::zkp::dm1;
struct PrivatePolicy { static constexpr bool pad_encoding_random=true,enable_code_check=false,enable_linear_check=false,enable_quadratic_check=false; };
struct PublicPolicy { static constexpr bool pad_encoding_random=false,enable_code_check=false,enable_linear_check=false,enable_quadratic_check=false; };
V input(){size_t n;std::cin>>n;V a(n);for(auto& x:a)std::cin>>x;return a;}
V flat(const std::array<V,3>& a){V out;for(const auto& v:a)out.insert(out.end(),v.begin(),v.end());return out;}
template<class Policy> V manager(bool row_only=false,bool prefix=false){
 witness_manager<F,Policy> m(4,8);unsigned char key[32];for(int i=0;i<32;++i)key[i]=i;
 m.encoding_random_engine().init(key,params::iv);V out;
 m.register_mask_callback([&](mpz_vector& a,mpz_vector& b,mpz_vector& c){for(auto* v:{&a,&b,&c})out.insert(out.end(),v->begin(),v->end());});
 m.register_linear_callback([&](auto row){if(row_only)out.insert(out.end(),row.first.begin(),row.first.end());});
 if(row_only || prefix){for(unsigned long i=1;i<=4;++i){auto* w=m.acquire_witness(i);m.commit_release_witness(w);}m.process_reset_linear_row();}
 if(!row_only)m.process_masks();return out;
}
int main(int argc,char** argv){
 try {
  if(argc<2)return 2;std::string mode=argv[1];V out;
  const size_t k=8,n=32,ell=4;auto [wk,w2,wn]=F::generate_omegas(k,n);
  if(mode=="roots"){
   auto [a,b,c]=F::generate_omegas(8192,32768);(void)b;
   out={mpz_class(mul(power(c,4),a)==1),mpz_class(power(a,8192)==1 && power(a,4096)!=1),mpz_class(power(7,32768)==1)};
  } else if(mode=="encode")out=encode(input(),n,wk,wn);
  else if(mode=="encode2")out=encode(input(),n,w2,wn);
  else if(mode=="decode")out=decode(input(),k,wk,wn,std::stoul(argv[2]));
  else if(mode=="masks") {unsigned long ctr=0;out=flat(masks(k,ell,[&](){return mpz_class(++ctr);}));}
  else if(mode=="manager")out=manager<PrivatePolicy>();
  else if(mode=="row")out=manager<PrivatePolicy>(true);
  else if(mode=="prefix")out=manager<PrivatePolicy>(false,true);
  else if(mode=="public")out=manager<PublicPolicy>();
  else if(mode=="replay"){out={mpz_class(manager<PrivatePolicy>()==manager<PrivatePolicy>())};}
  else if(mode=="profile"){fixed_profile(8192,std::stoul(argv[2]),32768,192);out={1};}
  else if(mode=="dimensions"){dimensions(8,6,2);out={1};}
  else if(mode=="delta"){out=encode(input(),n,wk,wn,1);}
  else if(mode=="old-domain") {V a=input();transform(a,wk,true);a.resize(n);transform(a,wn);out={a[(n-4*3)%n]};}
  else if(mode=="product"){
   V a=input(),b=input(),c=input();a=encode(a,n,wk,wn);b=encode(b,n,wk,wn);c=encode(c,n,wk,wn);for(size_t i=0;i<n;++i)a[i]=mod(mul(a[i],b[i])-c[i]);out=decode(a,k,wk,wn,2*k-1);
  } else if(mode=="difference"){
   V a=encode(input(),n,wk,wn),b=encode(input(),n,wk,wn);for(size_t i=0;i<n;++i)a[i]=mod(a[i]-b[i]);out=decode(a,k,wk,wn,k);
  } else if(mode=="mask-check"){
   V a=input();canonical(a);if(a.size()!=2*k)throw std::invalid_argument("mask length");V coeff=a;transform(coeff,w2,true);if(coeff.back()!=0)throw std::invalid_argument("mask degree");
   mpz_class sum=0;for(size_t i=0;i<ell;++i){sum=mod(sum+a[2*i]);if(std::string(argv[2])=="quad" && a[2*i]!=0)throw std::invalid_argument("quadratic mask zero");}
   if(std::string(argv[2])=="linear" && sum!=0)throw std::invalid_argument("linear mask sum");out={1};
  } else if(mode=="statistic"){
   V u=input(),a=input();V c(k);for(size_t i=0;i<k;++i)c[i]=mod(7*u[i]+a[i]);V ce=encode(c,n,wk,wn);V decoded=decode(ce,k,wk,wn,k);for(size_t i=0;i<ell;++i)decoded[i]=0;V ue=encode(u,n,wk,wn),pe=encode(decoded,n,wk,wn);out={mod(7*ue[1]-pe[1])};
  } else if(mode=="exhaust"){
   struct Bad {size_t count=0;void operator()(mpz_class& x,size_t){++count;x=(mpz_class(1)<<256)-1;}} bad;
   bool released=false;try{auto a=masks(k,ell,[&](){mpz_class x;F::generate_random(x,bad);return x;});(void)a;released=true;}catch(const std::runtime_error&){}
   out={mpz_class(bad.count),mpz_class(released)};
  } else return 3;
  std::cout<<"[";for(size_t i=0;i<out.size();++i){if(i)std::cout<<",";std::cout<<"\""<<out[i]<<"\"";}std::cout<<"]\n";
 }catch(const std::invalid_argument&){std::cout<<"[\"rejected\"]\n";}catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}
}

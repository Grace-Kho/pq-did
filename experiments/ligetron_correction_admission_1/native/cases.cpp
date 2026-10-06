// Public synthetic CPU cases. No WASM, WebGPU, proof or private credential.
#include "prelude.hpp"
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <zkp/finite_field_gmp.hpp>
#include <zkp/random.hpp>
#include <zkp/pqdid_rng_exp1.hpp>
#include <util/portable_sample.hpp>
#include "legacy_query.hpp"

namespace vm = ligero::vm;
namespace z = ligero::vm::zkp;
namespace exp1 = z::pqdid_exp1;
using F = z::bn254_gmp;
using Query = z::hash_random_engine<z::sha256>;
static bool entropy_ok = true;
static unsigned entropy_calls = 0;
static int entropy_count = 0;
static unsigned char entropy_input[32]{};

extern "C" int __wrap_RAND_priv_bytes(unsigned char* out, int count) {
    ++entropy_calls;
    entropy_count = count;
    if (!entropy_ok || count != 32) return 0;
    std::copy_n(entropy_input, count, out);
    return 1;
}

void require(bool yes, const char* message) {
    if (!yes) throw std::runtime_error(message);
}
std::string hex(const unsigned char* data, size_t n) {
    constexpr char chars[] = "0123456789abcdef";
    std::string out;
    for (size_t i=0; i<n; ++i) {
        out += chars[data[i] >> 4]; out += chars[data[i] & 15];
    }
    return out;
}
exp1::digest seed(unsigned start=0) {
    exp1::digest s;
    for (size_t i=0;i<32;++i) s.data[i]=static_cast<unsigned char>(start+i);
    return s;
}
void key(unsigned char (&out)[32], unsigned start=0) {
    auto s=seed(start);std::copy_n(s.data,32,out);
}
template<class Engine> std::string bytes(Engine& e, size_t n) {
    std::vector<unsigned char> out(n);
    for (auto& c:out)c=e();
    return hex(out.data(),out.size());
}
std::string raw(vm::mpz_random_engine& e, size_t n=2) {
    std::string out;
    for(size_t i=0;i<n;++i){mpz_class v;e(v,32);if(i)out+=",";out+=v.get_str(16);}
    return out;
}
std::string fields(vm::mpz_random_engine& e, size_t n=4) {
    std::string out;
    for(size_t i=0;i<n;++i){mpz_class v;F::generate_random(v,e);if(i)out+=",";out+=v.get_str(16);}
    return out;
}
struct Engines {
    vm::mpz_random_engine c,l,q;
    Engines(){unsigned char k[32];key(k);exp1::init_challenge_engines(k,c,l,q);}
    vm::mpz_random_engine& role(unsigned i){return i==0?c:i==1?l:q;}
};
struct LastQuery:Query {
    using Query::Query;
    void last(){state_=std::numeric_limits<uint64_t>::max();offset_=cycle_size;exhausted_=false;}
};
struct Sequence {
    std::vector<mpz_class> values;
    size_t calls=0;
    size_t throw_at=std::numeric_limits<size_t>::max();
    void operator()(mpz_class& out,size_t n) {
        require(n==32,"candidate width");
        const size_t i=calls++;
        if(i==throw_at)throw std::runtime_error("synthetic-engine-failure");
        require(i<values.size(),"unexpected extra candidate");
        out=values[i]<<2;
    }
};

std::string run(const std::string& id) {
    if(id=="ENT-01") {
        key(entropy_input);unsigned char s[32]{};exp1::private_encoding_seed(s);
        require(entropy_calls==1 && entropy_count==32,"entropy request size/count");
        require(std::equal(s,s+32,entropy_input),"private seed preservation");
        vm::mpz_random_engine e;e.init(s,vm::params::any_iv);
        return hex(s,32)+"|"+raw(e,1);
    }
    if(id=="ENT-02") {
        entropy_ok=false;bool entered=false,released=false,failed=false;unsigned char s[32]{};
        try{exp1::private_encoding_seed(s);entered=true;released=true;}
        catch(const std::runtime_error& e){failed=std::string(e.what())=="Cannot obtain private encoding randomness";}
        require(failed && !entered && !released && entropy_calls==1,"fail-closed entropy helper");
        return "entropy-error|stage-entered=0|release=0";
    }
    if(id=="ENT-03-A" || id=="ENT-03-B") {
        unsigned char k[32];key(k,id.back()=='A'?0:32);std::string out;
        for(int i=0;i<3;++i){vm::mpz_random_engine e;e.init(k,vm::params::any_iv);if(i)out+='|';out+=raw(e);}
        return out;
    }
    if(id=="Q-01-A" || id=="Q-01-B") {Query e(seed(id.back()=='A'?0:32));return bytes(e,32);}
    if(id=="Q-02") {Query e(seed());return bytes(e,65);}
    if(id=="Q-03-partial" || id=="Q-03-full" || id=="Q-03-zero") {
        Query e(seed());bytes(e,id=="Q-03-full"?32:7);
        if(id=="Q-03-zero")e.seed();else e.seed(seed(32));return bytes(e,40);
    }
    if(id.starts_with("Q-04-")) {Query e(seed());e.discard(std::stoul(id.substr(5)));return bytes(e,40);}
    if(id=="Q-05") {
        LastQuery e(seed());e.last();auto out=bytes(e,32);bool failed=false;
        try{e();}catch(const std::overflow_error&){failed=true;}
        require(failed,"counter must not wrap");return out+"|overflow";
    }
    if(id=="Q-06") {
        legacy_query<z::sha256> a(seed()),b(seed(32));Query c(seed()),d(seed(32));
        return bytes(a,32)+"|"+bytes(b,32)+"|"+bytes(c,32)+"|"+bytes(d,32);
    }
    if(id=="F-01-zero" || id=="F-01-max") {
        Sequence s;s.values.push_back(id=="F-01-zero"?mpz_class(0):mpz_class(F::modulus-1));
        mpz_class out=19;F::generate_random(out,s);require(s.calls==1,"endpoint draws");return out.get_str(16)+"|1";
    }
    if(id=="F-02") {
        Sequence s;s.values={F::modulus,mpz_class((mpz_class(1)<<254)-1),mpz_class(7)};
        mpz_class out=19;F::generate_random(out,s);require(s.calls==3,"rejection draws");return out.get_str(16)+"|3";
    }
    if(id=="F-03") {
        Sequence s;s.values.assign(255,F::modulus);s.values.push_back(11);
        mpz_class out=19;F::generate_random(out,s);require(s.calls==256,"last success draws");return out.get_str(16)+"|256";
    }
    if(id=="F-04") {
        Sequence s;s.values.assign(256,F::modulus);mpz_class out=19;bool failed=false;
        try{F::generate_random(out,s);}catch(const std::runtime_error& e){failed=std::string(e.what())=="Field sampler exhausted";}
        require(failed && s.calls==256 && out==19,"exhaustion sentinel/count");return "exhausted|256|19";
    }
    if(id=="F-05") {
        Sequence s;s.values={F::modulus};s.throw_at=1;mpz_class out=19;bool failed=false;
        try{F::generate_random(out,s);}catch(const std::runtime_error& e){failed=std::string(e.what())=="synthetic-engine-failure";}
        require(failed && s.calls==2 && out==19,"engine error propagation");return "engine-error|2|19";
    }
    if(id.starts_with("D-01-") || id.starts_with("D-02-")) {
        unsigned role=std::stoul(id.substr(5));require(role<3,"role");Engines a;
        auto first=fields(a.role(role));
        if(id.starts_with("D-02-")){Engines b;return first+"|"+fields(b.role(role));}return first;
    }
    if(id=="D-03") {
        vm::mpz_random_engine e;unsigned char k[32];key(k);e.init(k,vm::params::ivc);raw(e,1);e.init(k,vm::params::ivc);return raw(e);
    }
    if(id=="D-04") {
        vm::mpz_random_engine e;unsigned char k[32];key(k);e.init(k,vm::params::ivc);
        for(int i=0;i<511;++i){mpz_class discard;e(discard,32);}return raw(e);
    }
    if(id=="I-01") {
        Query e(seed());std::vector<size_t> indices(32768),out;
        std::iota(indices.begin(),indices.end(),0);
        vm::portable_sample(indices.begin(),indices.end(),std::back_inserter(out),size_t(192),e);
        std::sort(out.begin(),out.end());require(out.size()==192,"query count");
        require(std::adjacent_find(out.begin(),out.end())==out.end() && out.back()<32768,"query uniqueness/range");
        Query e2(seed());std::iota(indices.begin(),indices.end(),0);std::vector<size_t> second;
        vm::portable_sample(indices.begin(),indices.end(),std::back_inserter(second),size_t(192),e2);
        std::sort(second.begin(),second.end());require(out==second,"query role agreement");
        std::string s;for(size_t i=0;i<out.size();++i){if(i)s+=',';s+=std::to_string(out[i]);}return s;
    }
    if(id=="I-02") {
        auto a=exp1::stage1_seed(seed(),seed(32));
        auto b=exp1::stage2_seed(seed(),{0,1,0xffffffff},{7,8},{9});
        return hex(a.data,32)+"|"+hex(b.data,32);
    }
    throw std::invalid_argument("unknown case");
}

int main(int argc,char** argv) {
    try {
        require(argc==2,"one case required");
        require(OpenSSL_version_num()==OPENSSL_VERSION_NUMBER,"OpenSSL header/runtime version");
        require(std::string(gmp_version)=="6.3.0","GMP version");
        auto output=run(argv[1]);
        std::cout<<"{\"case\":\""<<argv[1]<<"\",\"data\":\""<<output
                 <<"\",\"openssl\":\""<<OpenSSL_version(OPENSSL_VERSION)
                 <<"\",\"gmp\":\""<<gmp_version<<"\"}\n";
        return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}

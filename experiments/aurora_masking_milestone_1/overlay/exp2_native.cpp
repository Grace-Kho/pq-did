
#include <libff/algebra/fields/binary/gf192.hpp>
#include "libiop/bcs/bcs_common.hpp"
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <sstream>
using F=libff::gf192;
using Chain=libiop::blake2b_hashchain<F,std::string>;
using State=libiop::exp2_public_state;
std::string hex(const std::string& in) {
    static const char* d="0123456789abcdef"; std::string out;
    for(unsigned char c:in) {out+=d[c>>4];out+=d[c&15];} return out;
}
F field(const std::string& in) {
    if(in.size()!=24) throw std::invalid_argument("field adapter width");
    std::vector<uint64_t> words(3,0);
    for(size_t i=0;i<24;++i) words[i/8]|=uint64_t((unsigned char)in[i])<<(8*(i%8));
    F out; if(!out.from_words(words)) throw std::invalid_argument("field conversion"); return out;
}
struct Driver: libiop::bcs_protocol<F,std::string> {
    static libiop::bcs_transformation_parameters<F,std::string> params() {
        libiop::bcs_transformation_parameters<F,std::string> p;
        p.security_parameter=256; p.hash_enum=libiop::blake2b_type;
        p.hashchain_=std::make_shared<Chain>(256);
        p.pow_params_=libiop::pow_parameters(0,1); return p;
    }
    Driver(const std::string& e,bool grouped,unsigned version):bcs_protocol(params()) {
        num_prover_messages_at_end_of_round_=grouped ? std::vector<size_t>{1,2,2} :
            std::vector<size_t>{2,3,3};
        exp2_initialise(e,grouped,version);
    }
    void round(size_t r,const std::vector<std::string>& roots,
        const std::vector<std::vector<F>>& all) {run_hashchain_for_round(r,roots,all);}
    const State& state() {return exp2_chain().exp2_trace();}
};
void print(const State& t) {
    for(const auto& row:t.trace)
        std::cout<<"T "<<row.label<<" "<<hex(row.digest)<<" "<<row.preimage.size()<<"\n";
    for(const auto& r:t.records) std::cout<<"R "<<hex(r)<<"\n";
    for(size_t i=0;i<t.outputs.size();++i)
        std::cout<<(i==0 || i==3 ? "V ":"I ")<<
            (i==0 || i==3 ? hex(t.outputs[i]):t.outputs[i])<<"\n";
    std::cout<<"F "<<hex(t.digest)<<" "<<t.counter<<" "<<t.mode<<"\n";
}
std::string fingerprint(const State& s) {
    std::string out=s.digest+s.xdom+State::u(s.counter,8)+State::u(s.next_round,8)+
        State::u(s.next_challenge,8)+std::to_string(s.pending);
    for(const auto& r:s.trace) out+=r.label+r.preimage+r.digest;
    for(const auto& r:s.records) out+=r;
    for(const auto& r:s.outputs) out+=r;
    return out;
}
void reject(Driver& d,const std::function<void()>& operation) {
    auto old=d.state(); bool caught=false;
    try {operation();} catch(const std::invalid_argument&) {caught=true;}
    if(!caught || d.state().mode!="FAILED" || fingerprint(old)!=fingerprint(d.state()))
        throw std::runtime_error("unexpected rejection/atomicity result");
    caught=false;
    try {d.exp2_challenge(0,0);} catch(const std::invalid_argument&) {caught=true;}
    if(!caught || fingerprint(old)!=fingerprint(d.state())) throw std::runtime_error("sticky failure");
    std::cout<<"X "<<hex(old.digest)<<" "<<old.counter<<" "<<old.trace.size()<<"\n";
}
struct Legacy: Chain {Legacy():Chain(256){} std::string digest(){return internal_state_;}};
// Replay public RR records using independently parsed fields and the same native BCS caller.
struct Reader {
    const std::string& data; size_t at=0;
    std::string take(size_t n) {
        if(n>data.size()-at) throw std::runtime_error("record truncated");
        auto r=data.substr(at,n);at+=n;return r;
    }
    uint64_t number(size_t n) {uint64_t r=0;for(unsigned char c:take(n)) r=(r<<8)|c;return r;}
    void end(){if(at!=data.size()) throw std::runtime_error("record trailing bytes");}
};
void replay(Driver& d,const std::vector<std::string>& records) {
    std::vector<std::vector<F>> all;
    for(size_t r=0;r<records.size();++r) {
        Reader rr{records[r]};
        if(rr.take(rr.number(2))!="PQDID-AURORA-TRANSCRIPT-EXP2/round" || rr.number(4)!=3)
            throw std::runtime_error("record frame");
        auto rid=rr.take(rr.number(8)),rs=rr.take(rr.number(8)),ms=rr.take(rr.number(8));rr.end();
        if(rid!=State::u(r,4)) throw std::runtime_error("record round");
        Reader roots{rs},msgs{ms}; std::vector<std::string> rv;
        auto nr=roots.number(4);if(nr>2) throw std::runtime_error("root count");
        for(size_t i=0;i<nr;++i) rv.push_back(roots.take(64));roots.end();
        auto nm=msgs.number(4);if(nm>2) throw std::runtime_error("message count");
        for(size_t i=0;i<nm;++i) {
            auto nf=msgs.number(4);if(nf>2) throw std::runtime_error("field count");
            std::vector<F> v;for(size_t j=0;j<nf;++j) v.push_back(field(msgs.take(24)));all.push_back(v);
        }
        msgs.end(); d.round(r,rv,all);
        for(size_t c=0;c<State::challenges(r);++c) d.exp2_challenge(r,c);
    }
    d.exp2_finish();
}
int main(int argc,char** argv) {
    try {
        if(argc!=3) throw std::runtime_error("case and canonical file required");
        int n=std::stoi(argv[1]);if(n<1 || n>16) throw std::runtime_error("unlisted case");
        if(n==16) {
            Legacy a,b;a.absorb(std::string(64,0));b.absorb(std::string(64,1));
            if(a.digest()!=b.digest()) throw std::runtime_error("old control mismatch");
            std::cout<<"L "<<hex(a.digest())<<" "<<hex(State::hash(std::string(64,32)+std::string(64,0)))
                <<" "<<hex(State::hash(std::string(64,32)+std::string(64,1)))<<"\n";return 0;
        }
        std::ifstream input(argv[2],std::ios::binary);
        if(!input) throw std::runtime_error("canonical input I/O");
        std::string e((std::istreambuf_iterator<char>(input)),{});
        if(e.size()>32768) throw std::runtime_error("input cap");
        if(n==9 || n==12) {
            try {Driver bad(n==9 ? "":e,false,n==12 ? 1:2);}
            catch(const std::invalid_argument&) {std::cout<<"N\n";return 0;}
            throw std::runtime_error("initialisation accepted");
        }
        Driver d(e,n==8,2);
        std::string root(64,0),a(24,2),b(24,3);
        if(n==4) root[63]=1;if(n==5) a[23]=3;
        std::vector<std::vector<F>> all=n==8 ? std::vector<std::vector<F>>{{field(a),field(b)}} :
            n==7 ? std::vector<std::vector<F>>{{field(b)},{field(a)}} :
            std::vector<std::vector<F>>{{field(a)},{field(b)}};
        all.push_back({});
        std::vector<std::string> roots{root,std::string(64,1)};
        if(n==6) {reject(d,[&]{d.round(1,{},all);});return 0;}
        if(n==10) {roots[0].pop_back();reject(d,[&]{d.round(0,roots,all);});return 0;}
        if(n==11) {reject(d,[&]{d.exp2_chain().exp2_commit(0,roots,{std::string(23,2),b});});return 0;}
        d.round(0,roots,all);
        if(n==14) {reject(d,[&]{d.exp2_challenge(0,1);});return 0;}
        d.exp2_challenge(0,0);
        if(n==13) {reject(d,[&]{d.round(1,{},all);});return 0;}
        d.exp2_challenge(0,1);d.exp2_challenge(0,2);
        d.round(1,{},all);d.exp2_challenge(1,0);d.round(2,{},all);d.exp2_finish();
        Driver verifier(e,n==8,2);replay(verifier,d.state().records);
        if(fingerprint(verifier.state())!=fingerprint(d.state())) throw std::runtime_error("replay");
        if(n==15) {reject(d,[&]{d.round(3,{},all);});return 0;}
        print(d.state());std::cout<<"A replay-equal\n";
        return 0;
    } catch(const std::exception& error) {std::cerr<<error.what()<<"\n";return 1;}
}

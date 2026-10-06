"""Isolated native EXP2 patch inputs; never applied to the retained checkout."""

FRAMING = r'''
#ifndef LIBIOP_EXP2_PUBLIC_PILOT_HPP
#define LIBIOP_EXP2_PUBLIC_PILOT_HPP
#include <sodium/crypto_generichash_blake2b.h>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>
namespace libiop {
// Public synthetic diagnostics only. No native object-memory serialisation.
struct exp2_public_state {
    using B = std::string;
    using V = std::vector<B>;
    struct trace_row { B label, preimage, digest; };
    B digest, xdom, mode = "LIVE";
    std::vector<trace_row> trace;
    V records, outputs;
    bool grouped = false;
    uint64_t counter = 0;
    size_t next_round = 0, next_challenge = 0;
    int pending = -1;
    static B u(uint64_t value, size_t n) {
        if (n < 8 && value >= (uint64_t(1) << (8*n)))
            throw std::invalid_argument("integer width");
        B out(n, 0);
        for (size_t i=0; i<n; ++i) out[n-1-i] = char(value >> (8*i));
        return out;
    }
    static B frame(const B& label, const V& parts) {
        const B tag = "PQDID-AURORA-TRANSCRIPT-EXP2/" + label;
        size_t arity = label=="profile" ? 4 : label=="relation" ? 1 :
            label=="statement" ? 5 : label=="init" ? 1 :
            label=="round" ? 3 : label=="absorb" ? 4 : label=="challenge" ? 7 : 0;
        if (!arity || parts.size()!=arity) throw std::invalid_argument("frame arity");
        size_t size = 2 + tag.size() + 4;
        for (const auto& part:parts) {
            if (part.size()>65536 || size>65536-8 || part.size()>65536-size-8)
                throw std::invalid_argument("frame capacity");
            size += 8 + part.size();
        }
        B out = u(tag.size(),2) + tag + u(parts.size(),4);
        for (const auto& part:parts) out += u(part.size(),8) + part;
        return out;
    }
    static B hash(const B& input) {
        B out(64, 0);
        if (crypto_generichash_blake2b(reinterpret_cast<unsigned char*>(&out[0]),64,
            reinterpret_cast<const unsigned char*>(input.data()),input.size(),nullptr,0))
            throw std::runtime_error("native BLAKE2b failure");
        return out;
    }
    B record_hash(const B& label, const B& input) {
        B out=hash(input); trace.push_back({label,input,out}); return out;
    }
    static size_t challenges(size_t r) { return r==0 ? 3 : r==1 ? 1 : 0; }
    static std::pair<size_t,size_t> port(size_t r,size_t c) {
        return r==0 && c>0 ? std::make_pair(size_t(2),c==1 ? size_t(8):size_t(0)) :
            std::make_pair(size_t(1),size_t(192));
    }
    static B plan(bool grouped) {
        B out=u(3,4);
        for (size_t r=0;r<3;++r) {
            std::vector<size_t> ns=r==0 ? (grouped ? std::vector<size_t>{2} :
                std::vector<size_t>{1,1}) : r==1 ? std::vector<size_t>{0} :
                std::vector<size_t>{};
            out+=u(r,4)+u(r==0 ? 2:0,4)+u(ns.size(),4);
            for (auto n:ns) out+=u(n,4);
            out+=u(challenges(r),4);
            for (size_t c=0;c<challenges(r);++c) {
                auto p=port(r,c); out+=u(c,4)+u(p.first,1)+u(p.second,2);
            }
        }
        return out;
    }
    exp2_public_state(const B& canonical, bool group, unsigned version):grouped(group) {
        if (version!=2 || canonical.empty() || canonical.size()>32768)
            throw std::invalid_argument("initialisation input");
        const B proto="PQDID-AURORA-AUTH";
        B pid=record_hash("profile",frame("profile",{u(2,2),proto,
            "PUBLIC-HARNESS;F=2^192;rho=1/8;eta=1;pow=0;not-an-IOP",plan(group)}));
        B rid=record_hash("relation",frame("relation",{
            "PUBLIC-TRANSCRIPT-HARNESS-NOT-AUTHENTICATION"}));
        xdom=frame("statement",{u(2,2),proto,pid,rid,canonical});
        digest=record_hash("init",frame("init",{xdom}));
    }
    void live() const { if(mode!="LIVE") throw std::invalid_argument("not LIVE"); }
    void commit_body(size_t r,const V& roots,const V& messages) {
        live();
        if(r!=next_round || r>=3 || (pending>=0 && next_challenge!=challenges(pending)))
            throw std::invalid_argument("round order");
        std::vector<size_t> ns=r==0 ? (grouped ? std::vector<size_t>{2} :
            std::vector<size_t>{1,1}) : r==1 ? std::vector<size_t>{0} : std::vector<size_t>{};
        if(roots.size()!=(r==0 ? 2:0) || messages.size()!=ns.size())
            throw std::invalid_argument("round counts");
        B rs=u(roots.size(),4), ms=u(messages.size(),4);
        for(const auto& root:roots) {
            if(root.size()!=64) throw std::invalid_argument("root width");
            rs+=root;
        }
        for(size_t i=0;i<ns.size();++i) {
            if(messages[i].size()!=24*ns[i]) throw std::invalid_argument("field width");
            ms+=u(ns[i],4)+messages[i];
        }
        B rr=frame("round",{u(r,4),rs,ms});
        digest=record_hash("absorb-"+std::to_string(r),
            frame("absorb",{digest,u(r,4),u(counter,8),rr}));
        records.push_back(rr); pending=int(r); next_round=r+1; next_challenge=0;
    }
    B challenge_body(size_t r,size_t c) {
        live();
        if(pending<0 || size_t(pending)!=r || c!=next_challenge || c>=challenges(r) ||
            counter==std::numeric_limits<uint64_t>::max())
            throw std::invalid_argument("challenge order or counter");
        auto p=port(r,c);
        B block=record_hash("challenge-"+std::to_string(r)+"-"+std::to_string(c),
            frame("challenge",{xdom,digest,u(r,4),u(c,4),u(counter,8),u(p.first,1),u(p.second,2)}));
        B value;
        if(p.first==1) value=block.substr(0,24);
        else {
            uint64_t n=0;
            for(size_t i=0;i<8;++i) n|=uint64_t(static_cast<unsigned char>(block[i]))<<(8*i);
            value=std::to_string(p.second==0 ? 0 : n&((uint64_t(1)<<p.second)-1));
        }
        outputs.push_back(value); ++counter; ++next_challenge; return value;
    }
    void finish_body() {
        live();
        if(next_round!=3 || pending!=2 || next_challenge!=0)
            throw std::invalid_argument("incomplete finish");
        mode="FINISHED";
    }
};
} // namespace libiop
#endif
'''

MEMBERS = r'''
    private:
        std::unique_ptr<exp2_public_state> exp2_;
        bool exp2_attempted_ = false;
    public:
        bool exp2_active() const { return exp2_attempted_; }
        const exp2_public_state& exp2_trace() const {
            if(!exp2_) throw std::invalid_argument("no usable EXP2 object");
            return *exp2_;
        }
        void exp2_forbid_legacy() {
            if(exp2_active()) exp2_fail("legacy method unavailable in EXP2");
        }
        void exp2_fail(const std::string& reason) {
            if(exp2_) exp2_->mode="FAILED";
            throw std::invalid_argument(reason);
        }
        void exp2_initialise(const std::string& canonical, bool grouped, unsigned version) {
            if(exp2_attempted_) exp2_fail("no EXP2 reset");
            exp2_attempted_=true;
            if(security_parameter_!=256) exp2_fail("EXP2 digest profile");
            exp2_.reset(new exp2_public_state(canonical,grouped,version));
        }
        void exp2_commit(size_t r,const std::vector<std::string>& roots,
                         const std::vector<std::string>& messages) {
            try {
                auto trial=exp2_trace(); trial.commit_body(r,roots,messages);
                *exp2_=std::move(trial);
            } catch(...) { if(exp2_) exp2_->mode="FAILED"; throw; }
        }
        std::string exp2_challenge(size_t r,size_t c) {
            try {
                auto trial=exp2_trace(); auto result=trial.challenge_body(r,c);
                *exp2_=std::move(trial); return result;
            } catch(...) { if(exp2_) exp2_->mode="FAILED"; throw; }
        }
        void exp2_finish() {
            try {
                auto trial=exp2_trace(); trial.finish_body(); *exp2_=std::move(trial);
            } catch(...) { if(exp2_) exp2_->mode="FAILED"; throw; }
        }
'''

BCS_MEMBERS = r'''
    public:
        blake2b_hashchain<FieldT,MT_hash_type>& exp2_chain() {
            auto* value=dynamic_cast<blake2b_hashchain<FieldT,MT_hash_type>*>(hashchain_.get());
            if(!value) throw std::invalid_argument("EXP2 requires BLAKE2b hashchain");
            return *value;
        }
        void exp2_initialise(const std::string& canonical,bool grouped,unsigned version) {
            exp2_chain().exp2_initialise(canonical,grouped,version);
        }
        std::string exp2_challenge(size_t r,size_t c) { return exp2_chain().exp2_challenge(r,c); }
        void exp2_finish() { exp2_chain().exp2_finish(); }
'''

BCS_ROUND = r'''
    auto* exp2=dynamic_cast<blake2b_hashchain<FieldT,MT_root_hash>*>(this->hashchain_.get());
    if(exp2 && exp2->exp2_active()) {
        try {
            if(round>=this->num_prover_messages_at_end_of_round_.size())
                exp2->exp2_fail("round outside registered plan");
            const size_t lo=round ? this->num_prover_messages_at_end_of_round_[round-1] : 0;
            const size_t hi=this->num_prover_messages_at_end_of_round_[round];
            if(hi<lo || hi>prover_messages.size()) exp2->exp2_fail("incomplete messages");
            std::vector<std::string> messages;
            for(size_t i=lo;i<hi;++i) {
                if(prover_messages[i].size()>2) exp2->exp2_fail("message capacity");
                std::string packed;
                for(const auto& value:prover_messages[i]) {
                    auto words=value.to_words();
                    if(FieldT::ceil_size_in_bits()!=192 || words.size()!=3)
                        exp2->exp2_fail("unsupported field representation");
                    for(auto word:words) for(size_t b=0;b<8;++b) packed+=char(word>>(8*b));
                }
                messages.push_back(packed);
            }
            exp2->exp2_commit(round,round_MT_roots,messages);
            return; // Explicit EXP2 ports, never the unreviewed Aurora query scheduler.
        } catch(...) { exp2->exp2_fail("EXP2 BCS round failed"); }
    }
'''

HARNESS = r'''
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
'''

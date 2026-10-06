// Public-input native algebraic correspondence, not a cryptographic prover.
// Oracle polynomial operations below use schoolbook coefficients, never native FFT/division.
#include <libff/algebra/fields/binary/gf192.hpp>
#include "libiop/protocols/aurora_iop.hpp"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
using F = libff::gf192;
using P = std::vector<F>;
using namespace libiop;
void require(bool value, const std::string &reason) { if (!value) throw std::runtime_error(reason); }
std::string hx(F x) {
    std::ostringstream s; s << std::hex << std::setfill('0');
    auto w=x.to_words(); for(auto it=w.rbegin();it!=w.rend();++it) s<<std::setw(16)<<*it;
    return s.str();
}
void emit(const std::string& label,const P& p) {
    std::cout<<"VALUE "<<label; for(const F& x:p) std::cout<<" "<<hx(x); std::cout<<"\n";
}
P trim(P p) { while(p.size()>1 && p.back()==F::zero()) p.pop_back();return p; }
P add(P a,const P& b) {a.resize(std::max(a.size(),b.size()),F::zero());for(size_t i=0;i<b.size();++i)a[i]+=b[i];return trim(a);}
P mul(const P& a,const P& b) {P p(a.size()+b.size()-1,F::zero());for(size_t i=0;i<a.size();++i)for(size_t j=0;j<b.size();++j)p[i+j]+=a[i]*b[j];return trim(p);}
F at(const P& p,F x) {F y=F::zero();for(auto i=p.rbegin();i!=p.rend();++i)y=y*x+*i;return y;}
P scale(P p,F k) {for(F& x:p)x*=k;return trim(p);}
std::pair<P,P> divrem(P a,const P& b) {
    a=trim(a);auto d=trim(b);require(!(d.size()==1&&d[0]==F::zero()),"oracle zero divisor");
    P q(a.size()>=d.size()?a.size()-d.size()+1:1,F::zero());
    while(a.size()>=d.size() && !(a.size()==1&&a[0]==F::zero())) {
        size_t k=a.size()-d.size();F c=a.back()*d.back().inverse();q[k]+=c;
        for(size_t j=0;j<d.size();++j)a[k+j]-=c*d[j];a=trim(a);
    }return {trim(q),trim(a)};
}
P vanish(const P& points){P p{F::one()};for(F u:points)p=mul(p,P{-u,F::one()});return p;}
P evals(const P& p,const P& points){P v;for(F x:points)v.push_back(at(p,x));return v;}
P interpolate(const P& xs,const P& ys) {
    require(xs.size()==ys.size(),"oracle interpolation size");P out{F::zero()};
    for(size_t i=0;i<xs.size();++i){P p{F::one()};F den=F::one();for(size_t j=0;j<xs.size();++j)if(i!=j){p=mul(p,P{-xs[j],F::one()});den*=xs[i]-xs[j];}out=add(out,scale(p,ys[i]*den.inverse()));}return out;
}
P seq(size_t n,uint64_t first){P p;for(size_t i=0;i<n;++i)p.emplace_back(first+i);return p;}
P domain(size_t n,uint64_t shift=0){P p;for(size_t i=0;i<n;++i)p.emplace_back(uint64_t(i)^shift);return p;}
void same(const P& a,const P& b,const std::string& label){require(a==b,label);}
template<class Fun> void rejected(Fun f,const std::string& label){bool got=false;try{f();}catch(const std::invalid_argument&){got=true;}catch(const std::logic_error&){got=true;}require(got,label);}
struct IO: iop_protocol<F> {
    void finish(){seal_interaction_registrations();seal_query_registrations();}
    void coin(size_t id,P v){require(id<verifier_random_message_registrations_.size(),"fixture coin id");require(v.size()==verifier_random_message_registrations_[id].size(),"fixture coin length");verifier_random_messages_[id]=v;}
    P message(size_t id) const{return prover_messages_.at(id);}
    void mutate_beta(F delta){require(prover_messages_.at(0).size()==1,"fixture beta shape");prover_messages_[0][0]+=delta;}
    size_t nmessages() const{return prover_message_registrations_.size();}
    size_t ncoins() const{return verifier_random_message_registrations_.size();}
    size_t round_messages(size_t i) const{return num_prover_messages_at_end_of_round_.at(i);}
    P reg_sizes() const{P p;for(auto r:verifier_random_message_registrations_)p.emplace_back(r.size());return p;}
};
struct SC: batch_sumcheck_protocol<F> {
    using batch_sumcheck_protocol<F>::batch_sumcheck_protocol;
    void fixture(const P& g,const P& h){fixture_mask_g_=g;fixture_mask_h_=h;}
    prover_message_handle beta_handle() const{return paper_beta_handle_;}
    P mask_coeffs() const{return masking_poly_.coefficients();}
};
struct FRI: FRI_protocol<F> {
    using FRI_protocol<F>::FRI_protocol;
    std::vector<size_t> bounds(IO& io) const {std::vector<size_t> v;for(size_t i=1;i<oracle_handles_.size();++i)v.push_back(io.get_oracle_degree(oracle_handles_[i][0][0]));v.push_back(final_polynomial_degree_bound_);return v;}
    P terminal(IO& io){return io.receive_prover_message(final_polynomial_handles_[0][0]);}
    P fold(IO& io,size_t layer){return *io.get_oracle_evaluations(oracle_handles_.at(layer)[0][0]);}
};
FRI_protocol_parameters<F> fri_params(size_t D,size_t folds){
    FRI_protocol_parameters<F> p(1,1,FRI_soundness_type::proven,D,8,3,64,std::vector<size_t>(folds,1));
    p.override_security_parameters(1,1);p.enable_paper_masking();return p;
}
struct Reducer: LDT_instance_reducer<F,FRI_protocol<F>> {
    using LDT_instance_reducer<F,FRI_protocol<F>>::LDT_instance_reducer;
    void fixture(const P& z){fixture_masks_={z};}
    oracle_handle_ptr pad(){return blinding_vector_handles_[0];}
    void challenge(const P& c){combined_oracles_[0]->set_random_coefficients(c);}
    P combined(){return *IOP_.get_oracle_evaluations(std::make_shared<virtual_oracle_handle>(combined_oracle_handles_[0]));}
};
struct Lin: multi_lincheck<F> {
    using multi_lincheck<F>::multi_lincheck;
    void public_masks(){for(auto s:sumchecks_)s->public_fixture_mask(seq(8,2),seq(9,12));}
};
r1cs_constraint_system<F> zero_cs(){
    r1cs_constraint_system<F> c;c.primary_input_size_=1;c.auxiliary_input_size_=6;
    linear_combination<F> z;for(size_t i=0;i<8;++i)c.add_constraint(r1cs_constraint<F>(z,z,z));return c;
}
struct PublicParams: aurora_iop_parameters<F> {
    PublicParams(){security_parameter_=1;pow_bits_=0;RS_extra_dimensions_=3;make_zk_=true;paper_masking_=true;domain_type_=affine_subspace_type;extra_systematic_dims_=2;constraint_domain_dim_=3;variable_domain_dim_=3;summation_domain_dim_=3;codeword_domain_dim_=8;query_bound_=2;
        encoded_aurora_params_=encoded_aurora_parameters<F>(1,8,3,3,2,true,false,affine_subspace_type,true);
        LDT_reducer_params_=LDT_instance_reducer_params<F>(1,LDT_reducer_soundness_type::proven,8,20,19,true,true);
        FRI_params_=fri_params(20,2);
    }
};
void field_case(){
    const F high(uint64_t(1)<<63,0,0);const F mid(0,1,0);const F top(1,0,0);
    F encoded; require(encoded.from_words({0x0123456789abcdefULL,0xffeeddccbbaa0099ULL,0x8877665544332211ULL}),"native from_words");
    require(encoded==F(0x8877665544332211ULL,0xffeeddccbbaa0099ULL,0x0123456789abcdefULL),"native constructor/word convention");
    emit("field-products",P{high*F(2),mid*top,encoded});
    require(F::modulus_==0x87,"source modulus");
    std::cout<<"PATH libff::gf192::operator*;to_words;from_words\n";
}
void sc_case(int n){
    IO io;field_subset<F> H(8),L(256,F(256));auto hh=io.register_domain(H),lh=io.register_domain(L);
    auto ell=io.register_oracle("public ell",lh,17,false);
    SC sc(io,hh,lh,17,true,affine_subspace_type,true);sc.fixture(seq(8,2),seq(9,12));sc.register_masking_polynomial();
    sc.attach_oracle_for_summing(std::make_shared<oracle_handle>(ell),F::zero());sc.register_challenge();
    io.register_verifier_random_message(1); // public outer-round challenge, not a sumcheck coefficient
    sc.register_proof();io.finish();
    const P z=vanish(domain(8)),u=seq(8,2),v=seq(9,12),r=add(mul(z,v),u);
    const F beta=z[1]*u[7];
    P e=n==4?P{F::zero()}:add(mul(z,seq(9,41)),seq(7,71));
    const P p=add(r,e);const auto qr=divrem(p,z);P correction(8,F::zero());correction[7]=beta*z[1].inverse();const P g=add(qr.second,correction);
    if(n==9){rejected([&]{io.submit_prover_message(sc.beta_handle(),{});},"wrong beta length accepted");std::cout<<"OBS expected-rejection registered-message-length\n";return;}
    if(n==22){rejected([&]{sc.calculate_and_submit_proof();},"unsubmitted beta admitted");io.submit_oracle(ell,oracle<F>(evals(e,domain(256,256))));rejected([&]{io.signal_prover_round_done();},"missing beta admitted at round boundary");std::cout<<"OBS expected-rejection incomplete-early-round\n";return;}
    io.submit_oracle(ell,oracle<F>(evals(e,domain(256,256))));sc.submit_masking_polynomial();
    same(trim(sc.mask_coeffs()),trim(r),"unrestricted mask coefficients");require(u[7]!=F::zero(),"fixture top coefficient");same(io.message(0),P{beta},"disclosed beta");
    io.signal_prover_round_done();sc.calculate_and_submit_proof();io.signal_prover_round_done();
    auto hhnd=std::make_shared<oracle_handle>(sc.get_h_oracle_handle());auto ghnd=std::make_shared<virtual_oracle_handle>(sc.get_g_oracle_handle());
    same(*io.get_oracle_evaluations(hhnd),evals(qr.first,domain(256,256)),"native quotient values");
    if(n==3){require(z[1]!=F::one()&&z[1]!=F::zero(),"non-unit xi fixture");F sum=F::zero();for(F x:domain(8))sum+=at(r,x);require(sum==beta,"independent mask sum");emit("xi-beta",P{z[1],beta});}
    if(n==8){io.mutate_beta(F::one());sc.construct_verifier_state();P badcorrection(8,F::zero());badcorrection[7]=(beta+F::one())*z[1].inverse();P badg=add(qr.second,badcorrection);require(trim(badg).size()==8,"bad beta must violate strict degree7");same(*io.get_oracle_evaluations(ghnd),evals(badg,domain(256,256)),"bad beta constraint values");std::cout<<"OBS violated-g-degree-not-a-proof-rejection\n";}
    else {const P before=*io.get_oracle_evaluations(ghnd);sc.construct_verifier_state();same(before,evals(g,domain(256,256)),"native g vector");for(size_t k=0;k<256;++k){const F got=io.get_oracle_evaluation_at_point(ghnd,k,false);require(got==at(g,F(k^256)),"native g point/shifted vector mismatch");}require(trim(g).size()<=7,"strict g bound");emit("beta-h-g",P{beta,at(qr.first,F(256)),at(g,F(256))});}
    std::cout<<"PATH batch_sumcheck_protocol::register_masking_polynomial;register_challenge;register_proof;submit_masking_polynomial;calculate_and_submit_proof;construct_verifier_state;sumcheck_g_oracle::evaluated_contents;evaluation_at_point\n";
}
void reducer_case(int n){
    const field_subset<F> L(256,F(256));const std::vector<size_t> ds{20,9,7,20};const P z=seq(20,31);const std::vector<P> polys{seq(20,2),seq(9,4),seq(7,6),z};
    combined_LDT_virtual_oracle<F> v(L,ds,true);P coins=n==10?P(6,F::zero()):seq(6,7);if(n==12){coins=P(6,F::zero());coins[4]=F::one();}
    if(n==14){rejected([&]{v.set_random_coefficients(P(5,F::one()));},"wrong reducer coin count accepted");std::cout<<"OBS expected-rejection coin-count\n";return;}
    v.set_random_coefficients(coins);
    if(n==15){rejected([&]{v.evaluation_at_point(0,F(256),P(3,F::one()));},"missing reducer pad accepted");std::cout<<"OBS expected-rejection constituent-count\n";return;}
    std::vector<std::shared_ptr<P>> evaluations;for(const P& p:polys)evaluations.push_back(std::make_shared<P>(evals(p,domain(256,256))));
    P expected=z;for(size_t j=0;j<3;++j){P raised(20-ds[j],F::zero());raised.insert(raised.end(),polys[j].begin(),polys[j].end());expected=add(expected,add(scale(polys[j],coins[j]),scale(raised,coins[3+j])));}
    same(*v.evaluated_contents(evaluations),evals(expected,domain(256,256)),"native reducer vector");for(size_t k=0;k<256;++k){P point;for(const P& p:polys)point.push_back(at(p,F(k^256)));require(v.evaluation_at_point(k,F(k^256),point)==at(expected,F(k^256)),"native reducer point");}
    if(n==10){
        IO io;auto lh=io.register_domain(L);std::vector<oracle_handle_ptr> inputs;for(size_t j=0;j<3;++j)inputs.push_back(std::make_shared<oracle_handle>(io.register_oracle("public",lh,ds[j],false)));
        LDT_instance_reducer_params<F> p(1,LDT_reducer_soundness_type::proven,8,20,20,true,true);Reducer reducer(io,lh,p);reducer.fixture(z);
        std::shared_ptr<multi_LDT_parameter_base<F>> fp=std::make_shared<FRI_protocol_parameters<F>>(fri_params(20,2));reducer.set_LDT_params(fp);reducer.register_interactions(inputs);io.finish();
        for(size_t j=0;j<3;++j)io.submit_oracle(inputs[j],oracle<F>(evals(polys[j],domain(256,256))));reducer.submit_masking_polynomial();reducer.challenge(coins);same(reducer.combined(),evals(z,domain(256,256)),"native reducer registered unit pad");same(*io.get_oracle_evaluations(reducer.pad()),evals(z,domain(256,256)),"native reducer pad submission");require(io.reg_sizes()[0]==F(6),"native reducer registered exact2J coins");
    }
    emit("reducer",P{at(expected,F(256)),at(expected,F(511))});
    std::cout<<"PATH combined_LDT_virtual_oracle::set_random_coefficients;evaluated_contents;evaluation_at_point;LDT_instance_reducer::register_interactions;submit_masking_polynomial[N-10]\n";
}
void fri_case(int n){
    if(n==19){rejected([]{auto p=fri_params(21,2);(void)p;},"nondivisible FRI bound accepted");std::cout<<"OBS expected-rejection degree-divisibility\n";return;}
    const size_t rounds=n==17?3:2,D=n==17?24:20;IO io;field_subset<F> L(256,F(256));auto lh=io.register_domain(L);auto h=io.register_oracle("public input",lh,D,false);auto p=fri_params(D,rounds);FRI fri(io,p,lh,{std::make_shared<oracle_handle>(h)});fri.register_interactions();io.finish();
    const auto bounds=fri.bounds(io);require(bounds.size()==rounds,"fold bound count");for(size_t i=0;i<rounds;++i)require(bounds[i]==D/(size_t(1)<<(i+1)),"registered fold degree");P out;for(size_t d:bounds)out.emplace_back(d);emit("fold-bounds",out);
    if(n==18){
        P coeff=seq(20,3),points=domain(256,256),values=evals(coeff,points);
        io.submit_oracle(h,oracle<F>(values));for(size_t j=0;j<rounds;++j)io.coin(j,P{F(3+2*j)});io.signal_prover_round_done();fri.calculate_and_submit_proof();
        for(size_t j=0;j<rounds;++j){P nextpoints,nextvalues;F b=points[0]+points[1],challenge(3+2*j);for(size_t k=0;k<points.size();k+=2){F x0=points[k],x1=points[k+1];F y=values[k]+(values[k+1]-values[k])*(challenge-x0)*(x1-x0).inverse();nextvalues.push_back(y);nextpoints.push_back(x0*x0+b*x0);}points=nextpoints;values=nextvalues;if(j+1<rounds)same(fri.fold(io,j+1),values,"native entire-domain fold");}
        P xs(points.begin(),points.begin()+5),ys(values.begin(),values.begin()+5);P expected=interpolate(xs,ys);expected.resize(5,F::zero());same(fri.terminal(io),expected,"independent terminal coefficients");same(evals(expected,points),values,"terminal full-domain interpolation");emit("terminal",expected);
    }
    std::cout<<"PATH FRI_protocol::register_interactions;get_oracle_degree;calculate_and_submit_proof[N-18];evaluate_next_f_i_over_entire_domain[N-18];receive_prover_message[N-18]\n";
}
void io_case(int n){
    if(n==22){sc_case(n);return;}
    if(n==23){IO io;auto h=io.register_domain(field_subset<F>(8)),l=io.register_domain(field_subset<F>(256,F(256)));rejected([&]{SC sc(io,h,l,17,false,affine_subspace_type,true);},"non-ZK paper branch accepted");std::cout<<"OBS expected-rejection unsupported-non-ZK-branch\n";return;}
    if(n==24){IO io;auto h=io.register_domain(field_subset<F>(8)),l=io.register_domain(field_subset<F>(256,F(256)));auto a=io.register_oracle("public",l,17,false);SC sc(io,h,l,17,true,affine_subspace_type,true);rejected([&]{sc.attach_oracle_for_summing(std::make_shared<oracle_handle>(a),F::one());},"nonzero attached claim accepted");std::cout<<"OBS expected-rejection nonzero-attached-claim\n";return;}
    if(n==21){IO io;PublicParams p;auto cs=zero_cs();aurora_iop<F> a(io,cs,p);a.register_interactions();io.finish();require(io.round_messages(0)==1,"Aurora beta not in round0");require(io.nmessages()==2,"Aurora beta and terminal message count");same(io.reg_sizes(),P{F(1),F(3),F(16),F(1),F(1)},"actual alpha/triple/reducer/fold sizes");auto early=io.get_oracle_registrations_by_round(0);require(early.size()==6,"four base+sumcheck+reducer early oracles");std::cout<<"PATH aurora_iop::constructor;register_interactions;encoded_aurora_protocol::constructor;multi_lincheck::constructor;LDT_instance_reducer::constructor;FRI_protocol::register_interactions\n";return;}
    IO io;auto hh=io.register_domain(field_subset<F>(8)),lh=io.register_domain(field_subset<F>(256,F(256)));auto fz=io.register_oracle("fz",lh,10,false);std::vector<oracle_handle_ptr> ms;for(int j=0;j<3;++j)ms.push_back(std::make_shared<oracle_handle>(io.register_oracle("Mz",lh,10,false)));
    auto cs=std::make_shared<r1cs_constraint_system<F>>(zero_cs());std::vector<std::shared_ptr<sparse_matrix<F>>> matrices;for(auto type:all_r1cs_sparse_matrix_types)matrices.push_back(std::make_shared<r1cs_sparse_matrix<F>>(cs,type));
    basic_lincheck_parameters<F> params(1,3,true,affine_subspace_type,true);Lin lin(io,lh,hh,hh,1,matrices,std::make_shared<oracle_handle>(fz),ms,params);lin.public_masks();lin.register_challenge();lin.register_proof();io.finish();
    io.coin(0,P{F(3)});io.coin(1,P{F(2),F(3),F(4)});io.submit_oracle(fz,oracle<F>(P(256,F::zero())));for(auto h:ms)io.submit_oracle(h,oracle<F>(P(256,F::zero())));lin.submit_sumcheck_masking_polynomials();io.signal_prover_round_done();lin.calculate_and_submit_proof();io.signal_prover_round_done();lin.construct_verifier_state();
    P z=vanish(domain(8)),r=add(mul(z,seq(9,12)),seq(8,2));auto qr=divrem(r,z);P c(8,F::zero());c[7]=F(9);P g=add(qr.second,c);const auto handles=lin.get_all_oracle_handles();same(*io.get_oracle_evaluations(handles[0]),evals(r,domain(256,256)),"actual lincheck r");same(*io.get_oracle_evaluations(handles[1]),evals(qr.first,domain(256,256)),"actual lincheck h");same(*io.get_oracle_evaluations(handles[2]),evals(g,domain(256,256)),"actual lincheck g");require(io.ncoins()==2,"obsolete lincheck pair remains");
    std::cout<<"PATH multi_lincheck::register_challenge;register_proof;submit_sumcheck_masking_polynomials;calculate_and_submit_proof;construct_verifier_state;multi_lincheck_virtual_oracle::set_challenge;evaluated_contents\n";
}
int main(int argc,char** argv){
    try{require(argc==2,"one case id required");int n=std::stoi(argv[1]);require(n>=1&&n<=24,"case not in approved matrix");
        if(n==1)field_case();else if(n<=9)sc_case(n);else if(n<=15)reducer_case(n);else if(n<=19)fri_case(n);else io_case(n);
        std::cout<<"PASS N-"<<std::setfill('0')<<std::setw(2)<<n<<"\n";return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}
}

# Prepared estimator inputs — not executed

No Sage installation, local pinned estimator or estimator allowance exists for this
package. The [input record](estimator-plan.json) fixes the candidate mappings and
their limitations. Upstream commit
`53da5982597709ba0fdf94ea37a84d822310fd84` was inspected as source only, not installed.
No estimator cost is reported as a result of this assessment.

After a separately authorised isolated environment and budget exist, the following
are exact Sage/Python input recipes from that checkout. Invoke **one selected
recipe under its approved guard**, not this entire list as a sweep. First record
`git rev-parse HEAD` and `sage --version`; refuse a commit mismatch. Record the
Sage/dependency versions, CPU/memory, shape/reduction models and raw outputs.
These commands provide neither installation nor execution authorisation.

```sh
sage -python -c 'from estimator import LWE, ND; from estimator.reduction import ADPS16; p=LWE.Parameters(n=1280,q=8380417,Xs=ND.Uniform(-4,4),Xe=ND.Uniform(-4,4),m=1536,tag="MLDSA65-enhanced-full-t"); print(LWE.estimate(p,red_cost_model=ADPS16(mode="classical"),red_shape_model="gsa",jobs=1,catch_exceptions=False))'
sage -python -c 'from sage.all import oo; from estimator import SIS; from estimator.reduction import ADPS16; p=SIS.Parameters(n=1536,q=8380417,m=3072,length_bound=724481,norm=oo,tag="MLDSA65-SelfTarget-relaxation"); print(SIS.estimate(p,red_cost_model=ADPS16(mode="classical"),red_shape_model="lgsa",jobs=1,catch_exceptions=False))'
sage -python -c 'from sage.all import oo; from estimator import SIS; from estimator.reduction import ADPS16; p=SIS.Parameters(n=1536,q=8380417,m=2816,length_bound=1048184,norm=oo,tag="MLDSA65-strong-forgery-relaxation"); print(SIS.estimate(p,red_cost_model=ADPS16(mode="classical"),red_shape_model="lgsa",jobs=1,catch_exceptions=False))'
```

The recipes are source-reviewed and unexecuted; import/API compatibility remains
to be checked in that future environment. A separate reduction-cost sensitivity
may replace `mode="classical"` with `mode="quantum"`, with its own admitted run.
That label does not quantise every surrounding LWE/SIS attack step. Full default
`MATZOV/GSA`, `LWE.estimate.rough` (`ADPS16/GSA`) and `SIS.estimate.rough`
(`ADPS16/LGSA` here) are different models, not just different search thoroughness.
Do not compare their numbers without stating those differences.

The first recipe grants unavailable low public-key bits to the attacker. The
second relaxes sparse challenge and hash fixed-point constraints. The third has
a different objective. None is a complete concrete forgery analysis of final
ML-DSA-65 or of PQ-DID. The older `n=32,m=64` prototype is outside all three.

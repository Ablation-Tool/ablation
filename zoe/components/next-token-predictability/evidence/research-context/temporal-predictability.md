# Temporal predictability and the two-way bridge

This note is an exploratory extension of accessible volume. It is not a validated musical or timing experiment.

## From next-token probabilities to next-onset probabilities

Accessible volume can measure a forecast of the next musical onset if a model supplies a complete probability distribution over possible delays.

Let \(H_i\) be the musical history before event \(i\), and define a finite delay vocabulary:

\[
\mathcal O_\delta=\{\delta,2\delta,3\delta,\ldots,M\delta\}
\]

Here \(\delta\) is a fixed timing quantization, such as 10 ms or a tempo-relative subdivision. For each possible delay \(k\delta\), the timing model produces:

\[
p_i(k)=P(\text{next onset occurs after }k\delta\mid H_i)
\]

Accessible volume then applies with the same strict threshold rule:

\[
A_{\tau,i}(H_i)=\sum_{k=1}^{M}\mathbf 1[p_i(k)>\tau]
\]

A small count means only a few onset times remain plausible; a large count means many remain plausible. If four possible delays have probabilities \(0.70,0.20,0.08,0.02\), then at \(\tau=0.05\), \(A_{0.05,i}=3\).

If a model predicts note identities instead of onset delays, the measurement describes note-choice breadth, not timing predictability.

A tempo-independent alternative is to normalize each interval by seconds per beat \(B\):

\[
r_i=\frac{t_{i+1}-t_i}{B}
\]

A categorical next-interval model can then predict a distribution over discrete interval bins \(I_k\):

\[
p_i(k)=P(r_i\in I_k\mid H_i),\qquad
A_{\tau,i}=\sum_k\mathbf 1[p_i(k)>\tau]
\]

This preserves the same accessible-volume measurement while allowing tempo changes to be modeled separately. Procrustes alignment handles residual tempo and starting-position differences when rhythms are compared.

## Timing prediction error

Accessible volume describes forecast breadth, not whether the predicted onset time was correct. Keep a separate timing error:

\[
e_i=t_i-\hat t_i
\]

For example, \(\hat t_i=1.000\) seconds and \(t_i=1.020\) seconds gives \(e_i=20\) ms. Positive error means the event arrived later than predicted; negative error means it arrived earlier.

Across a sequence, summarize bias and variability with root-mean-square error:

\[
E=\sqrt{\frac{1}{n}\sum_{i=1}^{n}(t_i-\hat t_i)^2}
\]

Predictability depends on the prediction model. A metronomic model may find swing difficult to predict, while a model trained for swing may find it highly predictable. Complexity is not the same as unpredictability.

## Present-state evaluation and feedback

The present state can retain three different measurements without combining incompatible units:

\[
\mathcal S_i=(A_{\tau,i}(H_i),\ M_{\tau,i},\ e_i)
\]

- **Accessible volume:** how many alternatives remain plausible.
- **Accessible Momentum:** how that breadth changed between observations:
  \[
  M_{\tau,i}=A_{\tau,i}(H_i)-A_{\tau,i-1}(H_{i-1})
  \]
- **Timing prediction error:** whether the actual onset arrived early, late, or exactly as predicted.

A controller can use this state together with candidate actions, goals, and constraints:

\[
a_{i+1}=\pi(\mathcal S_i,\text{candidates}_i,\text{goal},\text{constraints})
\]

The feedback loop is:

```text
Predict the next event and its breadth
→ observe what actually happens and when
→ measure volume, momentum, and timing error
→ adjust the next instruction or candidate
→ record the new evidence and repeat
```

Accessible volume does not supply a direction or reward by itself. A separate policy and candidate semantics are still required.

## Multi-horizon accessible volume

The same measurement can be extended from the next token to a sequence of \(h\) future tokens. Let \(O\) be a finite token vocabulary, \(C_t\) the context at time \(t\), and \(a_{1:h}=(a_1,\ldots,a_h)\) a candidate continuation. A learned autoregressive model defines its conditional joint probability as:

\[
P_h(a_{1:h}\mid C_t)=\prod_{j=1}^{h}p(a_j\mid C_{t+j-1},a_{<j})
\]

The multi-horizon accessible volume counts complete candidate continuations whose joint probabilities strictly exceed the threshold:

\[
A^{(h)}_\tau(C_t)=\sum_{a_{1:h}\in O^h}\mathbf 1[P_h(a_{1:h}\mid C_t)>\tau]
\]

Its complement counts all remaining continuations:

\[
A^{c,(h)}_\tau(C_t)=|O|^h-A^{(h)}_\tau(C_t)
\]

At \(h=1\), this reduces to the original next-token accessible volume. At larger horizons, it measures the breadth of plausible multi-token futures under the model, context, and threshold. It is not a guarantee that the model will predict every future token correctly, nor does a narrow forecast establish that the selected continuation is correct.

Exact enumeration considers \(|O|^h\) continuations, so its cost grows exponentially with the horizon. Practical experiments need bounded candidate sets or explicitly identified approximations; an approximate count must not be presented as the exact sum over \(O^h\).

## Procrustes alignment of rhythmic landmarks

Before comparing two rhythms, align their onset times with a tempo scale and a starting-time shift:

\[
q_i\approx a p_i+b,\qquad a>0
\]

Here \(p_i\) are onsets in the first rhythm and \(q_i\) are onsets in the second. The scale \(a\) represents a tempo change, while \(b\) shifts the starting time. Choose \(a\) and \(b\) to minimize the residual:

\[
D(p,q)=\sqrt{\frac{1}{n}\sum_{i=1}^{n}\left(q_i-(ap_i+b)\right)^2}
\]

A zero residual means the relative timing structures match after alignment. A large residual means alignment cannot make the onsets coincide. This is a geometric distance between rhythms, not a measurement of forecast breadth.

Temporal reflection adds a separate transformation:

\[
p'_i=L-p_{n+1-i}
\]

The corresponding retrograde distance is:

\[
D_{\mathrm{retrograde}}=D(p,p')
\]

It describes how different a rhythm remains from its reverse after removing tempo and starting-position differences. At least three onsets are required for a meaningful structural comparison; two onsets can always be aligned by scaling and shifting, so an exact two-onset alignment says nothing interesting about the complete rhythm.

Procrustes distance measures **how different rhythms are**. Accessible volume measures **how open each next-onset forecast is**. These are related experiments, but they are not the same measurement.

## Song-level summaries and reversal

Each prediction produces its own count, forming a sequence:

\[
\mathbf A_\tau=[A_{\tau,1},A_{\tau,2},\ldots,A_{\tau,n}]
\]

The mean forecast breadth is:

\[
\overline A_\tau=\frac{1}{n}\sum_{i=1}^{n}A_{\tau,i}
\]

An original-versus-reversed comparison can then be defined:

\[
D_\tau=\overline A_{\tau,\mathrm{reverse}}-\overline A_{\tau,\mathrm{forward}}
\]

This measures whether reversing the sequence makes the next events broader or narrower **under the same predictor and comparison procedure**. A threshold sweep is more informative than one threshold.

Reversing a sequence does not merely reverse prediction error. The evidence available before each event changes, so forward and reversed predictions must be evaluated independently. Zero momentum means only that two counts are equal; it does not prove identical probabilities or accessible-set membership.

## Requirements and limitations

A numerical timing experiment needs:

1. Symbolic timing data, such as MIDI or detected onsets.
2. A fixed timing quantization.
3. A model that supplies the complete next-delay distribution.
4. A consistent procedure for forward and reversed comparisons.

The result belongs to the **model–context–quantization combination**, not to the song in absolute terms or to a listener's brain. Accessible volume measures forecast breadth, not correctness, safety, or complete future behavior. A separate timing model and actual observations are required to evaluate timing prediction error.

## Harmonic osculating extrapolator

The **Harmonic Osculating Predictor (HOP)** is a separate, unvalidated deterministic baseline for extrapolating hidden-state trajectories. Given states \(h_t\in\mathbb R^d\), define velocity, turning angle, and tempo ratio:

\[
v_t=h_t-h_{t-1},\qquad
\cos\theta_t=\frac{v_{t-1}\cdot v_t}{|v_{t-1}||v_t|},\qquad
s_t=\frac{|v_t|}{|v_{t-1}|}
\]

Let \(\Delta\theta_t=\theta_t-\theta_{t-1}\), and let \(R(\alpha)\) rotate vectors in the plane of the last three states. The proposed extrapolation is:

\[
\hat h_{t+n}=h_t+\sum_{k=1}^{n}s_t^k\,R(\theta_t+(k-1)\Delta\theta_t)\,v_t
\]

**HOP cannot supply accessible volume by itself.** A predicted point \(\hat h_{t+n}\) is one geometric forecast, not a probability distribution over alternatives. Accessible volume requires either the model's full softmax distribution or a probabilistic HOP variant whose observed prediction errors are calibrated and discretized into timing bins. Taking `argmax` discards the alternative structure that accessible volume measures.

### Corrections and unresolved assumptions

HOP is a synthesis of geometry and musical metaphors, not an equation established by the referenced books or by the current accessible-volume experiments. The following issues must remain explicit:

- With \(s_t=1\) and \(\Delta\theta_t=0\), the formula reduces to \(\hat h_{t+n}=h_t+nR(\theta_t)v_t\), a straight line rather than an osculating arc. Constant-curvature extrapolation requires composed rotations, such as \(R(k\theta_t)v_t\), or a recursive update; that is a different model requiring its own validation.
- The ordinary four-point cross-ratio requires four points on the same projective line. Arbitrary states in \(\mathbb R^d\) are generally not collinear, so departure from \(-1\) has no established meaning as a cadence detector.
- Curvature does not imply error growth of \(\varepsilon e^{\kappa n}\). An exact circular trajectory extrapolated with its correct circle can have zero error despite nonzero curvature. Predictor mismatch and system dynamics determine the error.
- Next-token selection is not always cosine similarity followed by `argmax`. Models may apply final normalization and a learned unembedding, and decoding may sample rather than maximize.
- Medusa and EAGLE do not validate HOP. They use learned prediction mechanisms. HOP's accuracy must be measured independently against the model's own predictions, persistence, and linear-extrapolation baselines.
- Curvature and entropy gates are optional ablations, not validated dissonance detectors.
- Finite context destroys information, so no finite geometric construction can guarantee recovery of every future state.

The strongest first experiment would use drum or MIDI onsets, a categorical next-interval predictor, and the accessible-volume threshold sweep. HOP can then be evaluated separately as a deterministic baseline, reporting top-\(k\) accuracy, calibration, baseline acceptance rates, and failures rather than claiming universal prediction.

## Native GEM landmark integration

The [native Procrustes landmark-alignment example](https://github.com/Ablation-Tool/graphics-environment-manager/tree/main/examples/landmark-alignment) in Ablation's Graphics Environment Manager connects the geometric step to actual session evidence:

```text
Selected Lab node
→ Procrustes alignment
→ Spatial IR landmarks and correspondence lines
→ VDI export and device checks
→ replayed geometry evidence
→ scoped Procrustes evidence for the human and agent
```

The native implementation includes the `gem landmarks` CLI, `GemLabHost.align_landmarks`, a GTK menu action, source/target/fitted objects, correspondence lines, `landmark-report.json`, and evidence chaining from replayed geometry. It explicitly records affine-rank limitations: two pairs cannot uniquely determine a full affine transform, and exact landmark residuals do not establish whole-shape, anatomical, or semantic correctness.

This is the implementation bridge for the Procrustes section above. It does not supply a next-onset probability distribution by itself, so accessible volume still requires a compatible probabilistic model.

## Background consulted

The following extracted chapters informed the geometry and timing framework; the unified HOP is an experimental synthesis, not a result presented by these books:

- **Geometry for Programmers**, Chapter 4, *Projective geometric transformations*: translation, scaling, rotation, composition, homogeneous coordinates, and inverse transformations.
- **Classical Geometry**, Chapter 7, *The Euclidean transformations or isometries*: rotations, reflections, translations, inverses, and distance preservation.
- **Learn Music Theory**, Chapters 1 and 3: rhythm, meter, tempo, note values, compound meter, and tuplets.


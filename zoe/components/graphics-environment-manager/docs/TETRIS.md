# Bounded Tetris and black-box feed experiments

## Reference and provenance

The reference implementation is Juliano Fernandes's MIT-licensed `julianolf/tetris`, downloaded at commit `a264b8b0bc34b622763bcac355a0cd8a8f5fe2e6` into `/home/cowboy/_re/tetris-py`.

It contains a 10×20 board, seven tetromino types, collision checks, gravity, line clearing, scoring, levels, and a next-piece display. It calls `random.choice`, so it does not implement a 7-bag randomizer or expose a deterministic seed. Its older Python/Pygame requirements make it a behavioral reference, not the official Tetris implementation and not the code used for this experiment.

`gem/tetris.py` is original code. It does not copy the reference implementation, its assets, or an official Tetris ROM. `PIECE_NAMES`, normalized four-cell rotation states, `SplitMix64`, snapshot hashes, and the report schema are explicit and inspectable.

## The bounded game

The default board is 10×20. Each current piece has a kind, integer position, and one of four normalized rotation states. A move or rotation is accepted only when every resulting cell is inside the board and unoccupied. Hard drop advances to the last valid row and locks the piece. Complete rows disappear. Every cleared row adds \(10n^2\) points, where \(n\) is the number of rows cleared in that lock.

The default gravity interval is 30 ticks and halves per level, bounded to at least one tick. This is deliberately simple rather than a complete guideline implementation: there are no SRS wall kicks, hold queue, T-spin detection, combo system, networking, or medical/biological claims.

Two randomizers are supported:

- `uniform`: each of the seven types has probability \(1/7\) on every draw, independently.
- `bag`: a shuffled bag contains one of each type, and pieces are drawn without replacement. The bag resets after all seven have appeared.

The current and next pieces are both drawn during initialization, so the initial report has five pieces remaining in the bag. The PRNG state is included in snapshots, allowing an exact replay rather than merely a similar-looking game.

## Computational complexity boundary

Generalized Tetris decision problems can be **NP-complete**, depending on the board, rules, and objective. Some restricted variants are also hard, while others are polynomial. A fixed 10×20 board has a finite state space, but that does not make exhaustive placement search practical or turn the implementation into an NP-completeness proof.

This experiment performs legal moves, gravity, collision checks, and exact randomizer arithmetic. It does not solve board clearing, survival, optimal placement, or approximation problems. Exact bag probabilities are not claims about computational hardness. See [Demaine, Hohenberger, and Liben-Nowell’s Tetris work](https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-spring-2008/cdc627fbd05edbe0e9a480e45c8c827e_lec14.pdf) and the later [restricted-board results](https://arxiv.org/html/2009.14336v1) for the distinctions.

## Exact accessible outcomes

For a next-piece distribution \(p\), the accessible set at threshold \(\tau\) is

\[
A_\tau(S)=\sum_{i=1}^{7}\mathbf 1[p_i>\tau].
\]

The complement is \(|S|-A_\tau(S)\). The comparison is strictly greater than the threshold, not greater-than-or-equal.

For a bag with \(r\) pieces remaining, the next-piece support has \(r\) equally likely outcomes, each with probability \(1/r\). At initialization that is five outcomes at \(1/5\).

For two future draws from a bag with \(r\) remaining, there are \(r(r-1)\) ordered sequences, each with probability

\[
\frac{1}{r(r-1)}.
\]

The bag model is therefore **not** independent sampling. Uniform draws instead have \(7^h\) ordered sequences at horizon \(h\), each with probability \(7^{-h}\). Joint probabilities are enumerated exactly up to three pieces, including a bag refill at a boundary. The report's outcome support is the number of sequences with nonzero probability; it does not assume every sequence is possible.

At the preserved initial seed, a two-piece bag has **20 outcomes at probability \(1/20\)**. Therefore:

- \(A_{0.02}=20\), with complement zero.
- \(A_{0.05}=0\), with complement 20 because the comparison is strict.

These are exact probabilities under the declared randomizer, not probabilities of winning, enjoying, or learning.

## Candidate-model Bayesian comparison

`randomizer_posterior` compares independent-uniform and bag models with equal prior weight. Likelihoods use the declared sampling rules, and `bag_position` identifies where an observed sequence begins within a seven-piece cycle.

After observing all seven types once, the example posterior is:

- bag: **0.9939173263**
- independent uniform: **0.0060826737**

A repeated type before the bag resets has likelihood zero under the bag model. This is candidate-model inference, not identification of an unknown implementation's RNG.

## Native game and exports

```bash
python -m gem tetris
python -m gem tetris --randomizer uniform --horizon 2 --output tetris.json
python -m gem tetris --horizon 2 --output tetris.svg
python -m gem tetris --horizon 3 --output tetris.gem
```

Controls:

- Left/right arrows: move.
- Up arrow or Z: rotate clockwise/counterclockwise.
- Down arrow: soft drop.
- Space: hard drop.
- P: pause.
- S: one drop step.
- R: reset with the same seed and model.
- B: future draws use a bag.
- U: future draws use independent uniform sampling.

SVG, PNG, and GEM exports use the renderer-neutral scene. JSON contains the complete grid, current and next pieces, remaining bag, PRNG state, probability support, and snapshot SHA-256. Existing files are never overwritten. VR is marked inactive; no headset is accessed.

The preserved scene is [`images/bounded-tetris.png`](images/bounded-tetris.png), and the initial evidence is [`../evidence/tetris/experiment.json`](../evidence/tetris/experiment.json).

## Binary feed experiment

`gem feed` evaluates a separate black-box model for chronological like/not-like observations. Input can be JSON booleans or objects of the form `{"outcome":"like"}` or `{"outcome":"not_like"}`. At least 40 observations are required.

```bash
python -m gem feed observations.json --output feed-report.json
python -m gem feed observations.json --alpha .5 --train 24 --test 8
```

Three models are compared:

1. Independence: all observations share one estimated like probability.
2. First order: the next outcome depends only on the previous outcome.
3. Second order: the next outcome depends on the previous two outcomes.

A symmetric Dirichlet prior of strength \(\alpha\) smooths every conditional estimate, preventing zero-probability outcomes. Training windows expand chronologically; later windows remain held out. No future observations enter fitting.

The synthetic alternating sequence has held-out mean log losses:

- independence: **0.693147**
- first order: **0.114625**
- second order: **0.198193**

The first-order model wins on that sequence. This does not establish causation, reveal TikTok's proprietary algorithm, or prove that the same model wins on other feeds. A real experiment requires an authorized observation log and should test whether history improves held-out predictions compared with the independence baseline.

The preserved synthetic input is [`../evidence/feed/alternating.json`](../evidence/feed/alternating.json), and its report is [`../evidence/feed/report.json`](../evidence/feed/report.json).

## VR and biological boundaries

Tetris can motivate an optional VR adapter only if bodily manipulation or spatial audio adds something essential. A flat board placed inside a headset is not automatically a new experience. Any future design must preserve board readability, restrained camera movement, comfortable interaction, and a non-VR alternative. No headset or camera is activated by this implementation.

Electrical and biological models belong in a different synthetic experiment. A passive membrane circuit can be explored with explicit resistance, capacitance, current, position, and time, but Ohm's law is not a universal law of neural activity, and sensor measurements do not uniquely determine internal brain impulses. No biological or clinical prediction is made here.

## Verification

```bash
stress/nested_x11.sh env PYTHONPATH=. \
  /usr/bin/python3 -m unittest tools.test_tetris tools.test_feed -v
```

The tests cover rotation connectivity, exact bag/uniform supports, line clearing, gravity and level changes, deterministic replay, posterior comparison, scene/VDI verification, native controls, CLI exports, chronological feed validation, and negative cases.

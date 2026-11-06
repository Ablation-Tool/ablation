# Landmark alignment: two correspondences from four marked points

This worked example extracts the four marked landmark **points** in Figure 2.1 and pairs them into **two correspondences**. It does not invent four pairs: the image contains two points on the red lion and two on the blue unicorn.

The caption is “Aligning two shapes by minimizing the distance of corresponding landmark points,” from **Linear Algebra?** by Daniel Cohen-Or, Olga Sorkine-Hornung, and Chen Greif.

## Extracted correspondences

Coordinates are estimated to the nearest pixel from the supplied 554 × 659 screenshot. The coordinate convention is **x rightward, y downward**.

| Correspondence | Red source \((x_1,y_1)\) | Blue target \((x_2,y_2)\) |
| --- | --- | --- |
| Lion nose → unicorn horn | \((83,467)\) | \((328,389)\) |
| Lion tail → unicorn tail | \((270,513)\) | \((485,560)\) |

Thus

\[
X=\begin{bmatrix}
83&467\\
270&513
\end{bmatrix},\qquad
Y=\begin{bmatrix}
328&389\\
485&560
\end{bmatrix}.
\]

The machine-readable coordinates are in [landmarks.json](landmarks.json).

## Similarity alignment

A 2D similarity transform maps a source column vector \(x_i\) to a target \(y_i\):

\[
y_i \approx sR x_i+t,
\]

where \(s>0\) is a uniform scale, \(R\) is orthogonal, and \(t\) is translation. For a proper rotation,

\[
R=\begin{bmatrix}
\cos\theta&-\sin\theta\\
\sin\theta&\cos\theta
\end{bmatrix},\qquad \det R=+1.
\]

An optional reflection uses \(\det R=-1\), which is relevant when comparing shapes facing opposite directions.

Center the points:

\[
\bar x=\frac1N\sum_i x_i,\qquad \bar y=\frac1N\sum_i y_i,
\]
\[
X_0=X-\bar x,\qquad Y_0=Y-\bar y.
\]

The least-squares Procrustes problem is

\[
\min_{s,R,t}\sum_{i=1}^{N}\left\|sR(x_i-\bar x)-(y_i-\bar y)\right\|^2.
\]

Compute the cross-covariance and its singular value decomposition:

\[
M=X_0^TY_0=U\Sigma V^T.
\]

For a proper rotation, let \(D=\operatorname{diag}(1,\det(VU^T))\). For reflection-allowed alignment, use \(D=I\). Then

\[
R=VDV^T,
\]
\[
s=\frac{\operatorname{tr}(\Sigma D)}{\|X_0\|_F^2},
\]
\[
t=\bar y-sR\bar x.
\]

The fitted target and per-landmark RMS residual are

\[
\hat Y=s(RX_0^T)^T+\bar y,
\qquad
\operatorname{RMS}=\sqrt{\frac1N\sum_i\|\hat y_i-y_i\|^2}.
\]

## Numerical proper-rotation solution

Running the example produces

\[
s=1.2054659568,
\]
\[
R=\begin{bmatrix}
0.83268640&-0.55374485\\
0.55374485&0.83268640
\end{bmatrix},
\]
\[
t=\begin{bmatrix}
556.4187677\\
-135.1671835
\end{bmatrix}.
\]

Here \(\det R=+1\) and \(\theta=33.624306^\circ\). Both transformed landmarks match the targets to floating-point precision; RMS is approximately \(4.0\times10^{-14}\), effectively zero for these rounded pixel coordinates.

A complex-number cross-check gives the same orientation-preserving transform. Put \(z_i=x_{i,1}+ix_{i,2}\) and \(w_i=y_{i,1}+iy_{i,2}\). Then \(w_i=cz_i+d\), with \(c=se^{i\theta}\):

\[
c=\frac{w_2-w_1}{z_2-z_1}
=1.0037751112+0.6675205609i,
\]
\[
|c|=1.2054659568,\qquad
d=w_1-cz_1=556.4187677-135.1671835i.
\]

## Reflection-allowed solution

Allowing \(\det R=-1\) gives another exact alignment:

\[
s=1.2054659568,
\]
\[
R=\begin{bmatrix}
0.48077714&0.87684283\\
0.87684283&-0.48077714
\end{bmatrix},
\]
\[
t=\begin{bmatrix}
-213.72447081\\
571.92339221
\end{bmatrix},
\qquad \det R=-1.
\]

This illustrates an important limitation: with only two pairs, both a proper similarity and an orientation-reversing orthogonal similarity can fit exactly. Exact landmark residuals do not establish a unique or anatomically meaningful interpretation of the whole shape.

## Full affine alignment

A full affine transform is

\[
y_i=Ax_i+t,
\qquad
A=\begin{bmatrix}a_{11}&a_{12}\\a_{21}&a_{22}\end{bmatrix}.
\]

It has six unknowns. For correspondence \(i\),

\[
\begin{bmatrix}
x_i&y_i&1&0&0&0\\
0&0&0&x_i&y_i&1
\end{bmatrix}
\begin{bmatrix}
a_{11}\\a_{12}\\t_x\\a_{21}\\a_{22}\\t_y
\end{bmatrix}
=
\begin{bmatrix}x'_i\\y'_i\end{bmatrix}.
\]

Stacking these rows gives \(D\theta=b\), solved by least squares with \(\theta=D^+b\), where \(D^+\) is the pseudoinverse. A unique full affine solution requires **three non-collinear correspondences** and design rank six.

The two pairs here provide four scalar equations, so \(\operatorname{rank}D=4<6\). The full affine transform is therefore **underdetermined**, not unique. `np.linalg.lstsq` can return a minimum-norm solution, but presenting that as the recovered affine alignment would be misleading. The example reports the rank instead of making that claim.

## Native Graphics Environment Manager integration

The example also runs inside the canonical Ablation graphical environment, following the same human/agent + unified-memory architecture shown in the supplied bicameral diagram and flow animation:

```text
Selected Lab node
  → Procrustes alignment
  → Spatial IR source and target landmarks + fitted points + connectors
  → VDI export and device checks
  → replayed geometry evidence
  → scoped Procrustes evidence for the human and agent
```

Run it through the shared Lab host:

```bash
gem landmarks examples/landmark-alignment/landmarks.json \
  --session /path/to/project-session
```

Use `--allow-reflection` for the orientation-reversing solution and `--json` for the complete report. The GTK node menu also provides **Align landmarks (Procrustes)**, with a JSON chooser and background execution.

Each run contains the normal `scene.json`, VDI variants, `preview.svg`, verification reports, and `landmark-report.json`. The Procrustes evidence is a child of the replayed geometry evidence and records the transform, residual RMS, affine rank, and scope limits. No model inference is used for this geometric example.

## Reproduce

From the repository root:

```bash
python examples/landmark-alignment/procrustes.py
```

Write the full JSON report:

```bash
python examples/landmark-alignment/procrustes.py --output /tmp/landmark-report.json
```

The reusable implementations are `gem.landmarks.similarity_procrustes` and `gem.landmarks.affine_procrustes`. The example uses approximate manually extracted pixel centers, not an automatic computer-vision detector.

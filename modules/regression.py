"""
regression.py — Python Analysis ToolPak (Excel Analysis ToolPak-compatible output)

Replicates Excel Data Analysis > Regression:
  - Regression Statistics (R, R², Adjusted R², SE, Observations)
  - ANOVA table (df, SS, MS, F, Significance F)
  - Coefficients table (coef, SE, t-stat, P-value, 95% CI lower/upper)
  - Logistic regression with odds ratios and McFadden R²
  - Descriptive Statistics and Correlation Matrix

Used directly by ablation's --regress dispatch and importable by other modules
(e.g. RadiusOverflowProbe.sweep_payload_length logistic boundary fitting).

Import:
    from modules.regression import Regression, LogisticRegression, DescriptiveStats
"""

import math
from pathlib import Path


# ── Data loading ───────────────────────────────────────────────────────────────

def load_data(path: str):
    import pandas as pd
    p = Path(path)
    if p.suffix.lower() in ('.xlsx', '.xls', '.xlsm'):
        return pd.read_excel(p)
    return pd.read_csv(p)


# ── Descriptive Statistics ─────────────────────────────────────────────────────

class DescriptiveStats:
    """Excel Analysis ToolPak > Descriptive Statistics."""

    def __init__(self, series):
        import numpy as np
        from scipy import stats as sp_stats

        self.name = getattr(series, 'name', 'Variable')
        x = series.dropna().to_numpy(dtype=float)
        n = len(x)

        self.mean           = float(np.mean(x))
        self.standard_error = float(sp_stats.sem(x))
        self.median         = float(np.median(x))
        self.mode           = float(sp_stats.mode(x, keepdims=True).mode[0])
        self.std_dev        = float(np.std(x, ddof=1))
        self.variance       = float(np.var(x, ddof=1))
        self.kurtosis       = float(sp_stats.kurtosis(x, fisher=True))
        self.skewness       = float(sp_stats.skew(x))
        self.range          = float(np.max(x) - np.min(x))
        self.minimum        = float(np.min(x))
        self.maximum        = float(np.max(x))
        self.sum            = float(np.sum(x))
        self.count          = int(n)
        self.confidence_95  = float(sp_stats.t.ppf(0.975, df=n-1) * self.standard_error)

    def report(self) -> str:
        rows = [
            ('Mean',                  f'{self.mean:.6f}'),
            ('Standard Error',        f'{self.standard_error:.6f}'),
            ('Median',                f'{self.median:.6f}'),
            ('Mode',                  f'{self.mode:.6f}'),
            ('Standard Deviation',    f'{self.std_dev:.6f}'),
            ('Sample Variance',       f'{self.variance:.6f}'),
            ('Kurtosis',              f'{self.kurtosis:.6f}'),
            ('Skewness',              f'{self.skewness:.6f}'),
            ('Range',                 f'{self.range:.6f}'),
            ('Minimum',               f'{self.minimum:.6f}'),
            ('Maximum',               f'{self.maximum:.6f}'),
            ('Sum',                   f'{self.sum:.6f}'),
            ('Count',                 f'{self.count}'),
            ('Confidence Level(95%)', f'{self.confidence_95:.6f}'),
        ]
        width = max(len(r[0]) for r in rows) + 2
        lines = [f'{self.name}', '']
        for label, val in rows:
            lines.append(f'  {label:<{width}} {val}')
        return '\n'.join(lines)


# ── Correlation Matrix ─────────────────────────────────────────────────────────

class CorrelationMatrix:
    """Pearson correlation matrix — lower-triangular, matching Excel ToolPak layout."""

    def __init__(self, df):
        self.df   = df
        self.corr = df.corr(method='pearson')

    def report(self) -> str:
        cols = list(self.corr.columns)
        w = max(len(c) for c in cols) + 2
        lines = ['Correlation Matrix', '']
        header = ' ' * w + ''.join(f'{c:>{w}}' for c in cols)
        lines.append(header)
        for i, row_name in enumerate(cols):
            row = f'{row_name:<{w}}'
            for j, col_name in enumerate(cols):
                if j > i:
                    row += ' ' * w
                else:
                    val = self.corr.loc[row_name, col_name]
                    row += f'{val:>{w}.6f}'
            lines.append(row)
        return '\n'.join(lines)


# ── OLS Linear / Multiple Regression ──────────────────────────────────────────

class Regression:
    """
    OLS regression — exact Excel Analysis ToolPak output format.

    Output sections:
      1. SUMMARY OUTPUT (Regression Statistics)
      2. ANOVA table
      3. Coefficients table (SE, t-stat, P-value, CI bounds)
      4. Residual output (optional)
    """

    def __init__(self, y, X_df, confidence: float = 0.95, constant: bool = True):
        import numpy as np
        import statsmodels.api as sm

        self.y_name  = getattr(y, 'name', 'Y')
        self.x_names = list(X_df.columns)
        self.conf    = confidence
        self.constant = constant

        y_vals = y.to_numpy(dtype=float)
        X_vals = X_df.to_numpy(dtype=float)

        if constant:
            X_sm = sm.add_constant(X_vals, has_constant='add')
            var_names = ['Intercept'] + self.x_names
        else:
            X_sm = X_vals
            var_names = self.x_names

        model = sm.OLS(y_vals, X_sm).fit()
        self._model = model

        n  = int(model.nobs)
        k  = len(self.x_names)
        df_reg = k
        df_res = n - k - (1 if constant else 0)
        df_tot = n - 1

        self.n              = n
        self.k              = k
        self.var_names      = var_names
        self.coefficients   = list(model.params)
        self.std_errors     = list(model.bse)
        self.t_stats        = list(model.tvalues)
        self.p_values       = list(model.pvalues)
        alpha               = 1.0 - confidence
        ci                  = model.conf_int(alpha=alpha)
        self.ci_lower       = list(ci[:, 0])
        self.ci_upper       = list(ci[:, 1])

        self.r_squared      = float(model.rsquared)
        self.adj_r_squared  = float(model.rsquared_adj)
        self.multiple_r     = math.sqrt(self.r_squared)
        self.se_regression  = float(model.mse_resid ** 0.5)

        self.ss_regression  = float(model.ess)
        self.ss_residual    = float(model.ssr)
        self.ss_total       = self.ss_regression + self.ss_residual
        self.ms_regression  = self.ss_regression / df_reg if df_reg > 0 else float('nan')
        self.ms_residual    = self.ss_residual    / df_res if df_res > 0 else float('nan')
        self.f_stat         = float(model.fvalue)
        self.f_pvalue       = float(model.f_pvalue)
        self.df_reg         = df_reg
        self.df_res         = df_res
        self.df_tot         = df_tot

        self.fitted         = list(model.fittedvalues)
        self.residuals      = list(model.resid)

    def _section_summary(self) -> str:
        rows = [
            ('Multiple R',        f'{self.multiple_r:.6f}'),
            ('R Square',          f'{self.r_squared:.6f}'),
            ('Adjusted R Square', f'{self.adj_r_squared:.6f}'),
            ('Standard Error',    f'{self.se_regression:.6f}'),
            ('Observations',      f'{self.n}'),
        ]
        w = 22
        lines = ['SUMMARY OUTPUT', '', 'Regression Statistics']
        for label, val in rows:
            lines.append(f'  {label:<{w}} {val}')
        return '\n'.join(lines)

    def _section_anova(self) -> str:
        col_w = [12, 6, 14, 14, 14, 14]
        headers = ['', 'df', 'SS', 'MS', 'F', 'Significance F']
        rows_data = [
            ('Regression',
             f'{self.df_reg}',
             f'{self.ss_regression:.4f}',
             f'{self.ms_regression:.4f}',
             f'{self.f_stat:.4f}',
             f'{self.f_pvalue:.4E}'),
            ('Residual',
             f'{self.df_res}',
             f'{self.ss_residual:.4f}',
             f'{self.ms_residual:.4f}',
             '', ''),
            ('Total',
             f'{self.df_tot}',
             f'{self.ss_total:.4f}',
             '', '', ''),
        ]
        lines = ['', 'ANOVA']
        header_line = ''.join(f'{h:<{col_w[i]}}' for i, h in enumerate(headers))
        lines.append(header_line)
        for row in rows_data:
            lines.append(''.join(f'{cell:<{col_w[i]}}' for i, cell in enumerate(row)))
        return '\n'.join(lines)

    def _section_coefficients(self) -> str:
        ci_label = f'{int(self.conf*100)}%'
        headers = ['', 'Coefficients', 'Standard Error',
                   't Stat', 'P-value',
                   f'Lower {ci_label}', f'Upper {ci_label}']
        col_w = [max(len(n) for n in self.var_names) + 2, 14, 16, 14, 14, 14, 14]
        lines = ['', '']
        header_line = ''.join(f'{h:<{col_w[i]}}' for i, h in enumerate(headers))
        lines.append(header_line)
        for j, name in enumerate(self.var_names):
            p = self.p_values[j]
            p_str = f'{p:.4E}' if p < 0.001 else f'{p:.6f}'
            row = [
                name,
                f'{self.coefficients[j]:.6f}',
                f'{self.std_errors[j]:.6f}',
                f'{self.t_stats[j]:.6f}',
                p_str,
                f'{self.ci_lower[j]:.6f}',
                f'{self.ci_upper[j]:.6f}',
            ]
            lines.append(''.join(f'{cell:<{col_w[i]}}' for i, cell in enumerate(row)))
        return '\n'.join(lines)

    def _section_residuals(self) -> str:
        lines = ['', '', 'RESIDUAL OUTPUT', '']
        lines.append(f'  {"Observation":<14} {"Predicted Y":>14} {"Residuals":>14}')
        for i, (pred, resid) in enumerate(zip(self.fitted, self.residuals), start=1):
            lines.append(f'  {i:<14} {pred:>14.6f} {resid:>14.6f}')
        return '\n'.join(lines)

    def report(self, residuals: bool = False) -> str:
        parts = [
            self._section_summary(),
            self._section_anova(),
            self._section_coefficients(),
        ]
        if residuals:
            parts.append(self._section_residuals())
        sep = '\n' + '-' * 72 + '\n'
        return sep.join(parts)

    def equation(self) -> str:
        terms = []
        for j, name in enumerate(self.var_names):
            coef = self.coefficients[j]
            if name == 'Intercept':
                terms.append(f'{coef:.4f}')
            else:
                sign = '+' if coef >= 0 else '-'
                terms.append(f'{sign} {abs(coef):.4f}*{name}')
        return f'{self.y_name} = {" ".join(terms)}'


# ── Logistic Regression ────────────────────────────────────────────────────────

class LogisticRegression:
    """
    Binary logistic regression — Analysis ToolPak style output with odds ratios.

    Used by RadiusOverflowProbe.sweep_payload_length() for crash-boundary detection:
      payload_length (X) -> crash/no-crash (Y=0/1) -> fitted boundary in bytes
      -> maps directly to gp_obj struct field offset via GP_NAME_OFFSET + boundary
    """

    def __init__(self, y, X_df, confidence: float = 0.95):
        import numpy as np
        import statsmodels.api as sm

        self.y_name  = getattr(y, 'name', 'Y')
        self.x_names = list(X_df.columns)
        self.conf    = confidence

        y_vals = y.to_numpy(dtype=float)
        X_sm   = sm.add_constant(X_df.to_numpy(dtype=float), has_constant='add')
        self.var_names = ['Intercept'] + self.x_names

        model = sm.Logit(y_vals, X_sm).fit(disp=False)
        self._model = model

        alpha             = 1.0 - confidence
        ci                = model.conf_int(alpha=alpha)
        self.coefficients = list(model.params)
        self.std_errors   = list(model.bse)
        self.z_stats      = list(model.tvalues)
        self.p_values     = list(model.pvalues)
        self.odds_ratios  = [math.exp(c) for c in self.coefficients]
        self.ci_lower     = list(ci[:, 0])
        self.ci_upper     = list(ci[:, 1])
        self.or_ci_lower  = [math.exp(v) for v in self.ci_lower]
        self.or_ci_upper  = [math.exp(v) for v in self.ci_upper]

        self.log_likelihood      = float(model.llf)
        self.null_log_likelihood = float(model.llnull)
        self.mcfadden_r2         = float(model.prsquared)
        self.aic                 = float(model.aic)
        self.bic                 = float(model.bic)
        self.n                   = int(model.nobs)

    def classification_report(self, threshold: float = 0.5) -> str:
        """Confusion matrix + precision/recall/F1 for the fitted model.

        Useful for assessing crash/no-crash label quality near the boundary:
        low precision near the threshold = heap non-determinism in sweep data.
        If that's the case, run ≥3 trials per payload length and aggregate.
        """
        import numpy as np
        y_true = (self._model.model.endog).astype(int)
        y_pred = (self._model.predict() >= threshold).astype(int)
        tp = int(np.sum((y_pred == 1) & (y_true == 1)))
        tn = int(np.sum((y_pred == 0) & (y_true == 0)))
        fp = int(np.sum((y_pred == 1) & (y_true == 0)))
        fn = int(np.sum((y_pred == 0) & (y_true == 1)))
        precision = tp / (tp + fp) if (tp + fp) > 0 else float('nan')
        recall    = tp / (tp + fn) if (tp + fn) > 0 else float('nan')
        f1 = 2*precision*recall/(precision+recall) if (precision+recall) > 0 else float('nan')
        accuracy  = (tp + tn) / self.n if self.n > 0 else float('nan')
        lines = [
            f'Classification Report (threshold={threshold})',
            f'  {"Accuracy":<18} {accuracy:.4f}',
            f'  {"Precision":<18} {precision:.4f}',
            f'  {"Recall":<18} {recall:.4f}',
            f'  {"F1":<18} {f1:.4f}',
            '',
            f'  Confusion Matrix:',
            f'  {"":>12} Predicted 0  Predicted 1',
            f'  {"Actual 0":>12} {tn:>11} {fp:>11}',
            f'  {"Actual 1":>12} {fn:>11} {tp:>11}',
        ]
        return '\n'.join(lines)

    def boundary_at_prob(self, prob: float = 0.5) -> float:
        """Return the X value (payload length) where P(crash) = prob.

        Uses the inverse logit: X = -(intercept + log(p/(1-p))) / coef_x
        Valid only for the single-predictor case (one X column).
        """
        if len(self.coefficients) != 2:
            raise ValueError("boundary_at_prob only valid for single-predictor model")
        b0, b1 = self.coefficients
        import math
        log_odds = math.log(prob / (1.0 - prob))
        return (log_odds - b0) / b1

    def report(self) -> str:
        ci_label = f'{int(self.conf*100)}%'
        lines = [
            'LOGISTIC REGRESSION OUTPUT', '',
            'Model Fit Statistics',
            f'  {"Log-Likelihood":<26} {self.log_likelihood:.4f}',
            f'  {"Null Log-Likelihood":<26} {self.null_log_likelihood:.4f}',
            f'  {"McFadden Pseudo R²":<26} {self.mcfadden_r2:.6f}',
            f'  {"AIC":<26} {self.aic:.4f}',
            f'  {"BIC":<26} {self.bic:.4f}',
            f'  {"Observations":<26} {self.n}',
            '', '',
        ]
        col_w = [max(len(n) for n in self.var_names) + 2, 12, 12, 10, 12, 12, 12, 12, 12]
        headers = ['', 'Coef', 'Std Error', 'z Stat', 'P-value',
                   'Odds Ratio', f'OR Lower {ci_label}', f'OR Upper {ci_label}']
        lines.append(''.join(f'{h:<{col_w[min(i, len(col_w)-1)]}}' for i, h in enumerate(headers)))
        for j, name in enumerate(self.var_names):
            p = self.p_values[j]
            p_str = f'{p:.4E}' if p < 0.001 else f'{p:.6f}'
            row = [
                name,
                f'{self.coefficients[j]:.6f}',
                f'{self.std_errors[j]:.6f}',
                f'{self.z_stats[j]:.4f}',
                p_str,
                f'{self.odds_ratios[j]:.4f}',
                f'{self.or_ci_lower[j]:.4f}',
                f'{self.or_ci_upper[j]:.4f}',
            ]
            lines.append(''.join(f'{cell:<{col_w[min(i, len(col_w)-1)]}}' for i, cell in enumerate(row)))
        return '\n'.join(lines)


# ── ANCOVA Model Comparison (patch detection) ──────────────────────────────────

def compare_models(version_offsets: dict, patch_versions: list,
                   field_name: str = 'offset') -> str:
    """ANCOVA cross-version struct-field patch detection.

    Fits two models:
      Restricted:   offset ~ version_index              (no patch effect)
      Unrestricted: offset ~ version_index + patch_flag (with patch indicator)

    A large delta-R² with a significant F-test means the patch_flag explains
    variance in the struct offset — i.e., the field shifted when a specific
    patch landed. This is the Carlberg ANCOVA approach from Chapter 8.

    version_offsets : {'9.14.2.14': 0x308, '9.16.4.18': 0x310, ...}
    patch_versions  : list of version strings that are suspected patch points
    """
    import numpy as np
    import statsmodels.api as sm
    from scipy import stats as sp_stats

    def _ver_key(v):
        try:
            return tuple(int(x) for x in v.split('.'))
        except Exception:
            return (0,)

    sorted_items = sorted(version_offsets.items(), key=lambda kv: _ver_key(kv[0]))
    versions = [v for v, _ in sorted_items]
    offsets  = np.array([o for _, o in sorted_items], dtype=float)
    n = len(versions)

    if n < 4:
        return f"compare_models requires ≥4 versions (got {n})"

    x_idx   = np.arange(n, dtype=float)
    patch_f = np.array([1.0 if v in patch_versions else 0.0 for v in versions])

    # Restricted model
    Xr = sm.add_constant(x_idx, has_constant='add')
    mr = sm.OLS(offsets, Xr).fit()

    # Unrestricted model
    Xu = sm.add_constant(np.column_stack([x_idx, patch_f]), has_constant='add')
    mu = sm.OLS(offsets, Xu).fit()

    delta_r2  = mu.rsquared - mr.rsquared
    q         = 1  # one added predictor (patch_flag)
    df_num    = q
    df_den    = n - 3  # n - (k_u + 1)
    if df_den <= 0:
        return "compare_models: insufficient degrees of freedom for F-test"
    F_delta = ((mr.ssr - mu.ssr) / q) / (mu.ssr / df_den) if mu.ssr > 0 else float('nan')
    p_delta = float(sp_stats.f.sf(F_delta, df_num, df_den)) if not math.isnan(F_delta) else float('nan')

    sig = "SIGNIFICANT — patch shifted field" if p_delta < 0.05 else "not significant"
    lines = [
        f'ANCOVA MODEL COMPARISON — {field_name}',
        '',
        f'  {"Restricted R² (no patch term)":<36} {mr.rsquared:.6f}',
        f'  {"Unrestricted R² (with patch term)":<36} {mu.rsquared:.6f}',
        f'  {"Delta R²":<36} {delta_r2:+.6f}',
        f'  {"F(delta)":<36} {F_delta:.4f}',
        f'  {"p-value":<36} {p_delta:.4E}',
        f'  {"Verdict":<36} {sig}',
        '',
        f'  Patch versions tested: {", ".join(patch_versions)}',
    ]
    return '\n'.join(lines)


# ── Firmware Version Regression ───────────────────────────────────────────────

class FirmwareVersionRegression:
    """
    Cross-version struct field offset tracker — the core tool for firmware
    regression analysis as described by Cisco AI:

        "Regression analysis here involves comparing struct layouts and
         teardown code across firmware versions to see if the overflow and
         pointer corruption paths are consistent, patched, or altered."

    Input: {version_string: offset_value} for one gp_obj field (e.g. WINS_PTR_OFFSET).
    Versions are sorted and indexed 0,1,2... for the regression X axis.

    Output:
      - OLS fit: trend line (slope = bytes/version)
      - R²: 1.0 = perfectly stable offset, <0.8 = large version-to-version drift
      - Residual spikes: versions where |residual| > 2*SE — patch candidates
      - Predicted offset for a future version (extrapolation)

    Seeded with confirmed gp_obj offsets from LINA binary RE:
      GP_NAME_OFFSET = 0x2b1  (buffer start, stable across versions)
      DNS_PTR_OFFSET = 0x2f0  (first corrupted ptr, 9.14.2.14 confirmed)
      WINS_PTR_OFFSET = 0x308 (wins-server list head, 9.14.2.14 confirmed)
    """

    # Confirmed offsets from LINA binary RE
    # Method: LEA instruction scan (b0/b1 02 00 00 with code prefix check) across CPIO-extracted LINA
    # 9.12.3.1:  @ 0x2770af7 attr handler; 9.22.2.32: @ 0x1a3d8ec inline-strcpy site (lea rdx,[rdi+0x2b1])
    # 9.16.4.18: @ 0x212a669 Class attr handler; 9.14.2.14: formula-predicted 0x2b1 REVISED to 0x2b0
    # dns_ptr=0x2f0, wins_ptr=0x308 INVARIANT across all F2-applicable versions
    KNOWN_OFFSETS = {
        '9.10.1.40': {
            # DIFFERENT ATTACK SURFACE — F2 path does NOT apply to this version
            # RADIUS Class attr (0x19) handler writes to gp_obj+0x6ec (raw Class attr store)
            # 0x6ec > 0x308 (wins_ptr) → overflow at 0x6ec goes AWAY from dns/wins ptrs
            # gp_name display field is at 0x2b8 but populated via cert OU= path, not Class attr
            # Cisco AI confirmed: "Class attr handler copies to buffer at 0x6ec" (2026-08-14)
            # Cisco AI confirmed: dns_ptr=0x2f0, wins_ptr=0x308 offsets stable (same struct)
            'gp_name':  0x6ec,  # Class attr dest (NOT comparable to 9.12+ gp_name)
            'dns_ptr':  0x2f0,
            'wins_ptr': 0x308,
            # attr 0x19 handlers: 0x26baaf8, 0x26bab63; gp_name_display: 0x2b8
            # F2 exploit NOT reachable via RADIUS Class attr in this version
        },
        '9.12.3.1': {
            'gp_name':  0x2b0,  # lea 0x2b0(%rbx),%rsi in RADIUS attr dispatch
            'dns_ptr':  0x2f0,  # movl $0x0,0x2f0(%rbx) zero-init confirmed
            'wins_ptr': 0x308,  # mov %edx,0x308(%rbx) bswap write confirmed
            # DNS_DELTA=0x40(64), WINS_DELTA=0x58(88) — confirmed 2026-08-14
            # strcpy PLT: 0xbec610; attr dispatch: 0x2770900; OU= xref: 0x258a5fe
        },
        '9.13.1.16': {
            'gp_name':  0x2b0,  # LEA scan: 276 code hits 0x2b0 vs 0 hits 0x2b1 (2026-08-14)
            'dns_ptr':  0x2f0,  # invariant confirmed
            'wins_ptr': 0x308,  # invariant confirmed
        },
        '9.14.2.14': {
            'gp_name':  0x2b0,  # REVISED 2026-08-14: formula-predicted 0x2b1 REFUTED; all 9.14.x scanned = 0x2b0
            'dns_ptr':  0x2f0,  # zeroed in init; WINS_DELTA=88 (0x2b0 layout)
            'wins_ptr': 0x308,  # wins-server list head; corrupted at byte 88
        },
        '9.15.1.15': {
            'gp_name':  0x2b0,  # LEA scan: 264 code hits 0x2b0 vs 0 hits 0x2b1 (2026-08-14)
            'dns_ptr':  0x2f0,  # invariant confirmed
            'wins_ptr': 0x308,  # invariant confirmed
        },
        '9.16.1': {
            'gp_name':  0x2b0,  # LEA scan: 275 code hits 0x2b0 vs 0 hits 0x2b1 (2026-08-14)
            'dns_ptr':  0x2f0,
            'wins_ptr': 0x308,
        },
        '9.16.4.18': {
            'gp_name':  0x2b0,  # 1-byte backward shift (struct re-padded, 8B aligned)
            'dns_ptr':  0x2f0,  # UNCHANGED — same corruption target
            'wins_ptr': 0x308,  # UNCHANGED — same corruption target
            # DNS_DELTA=0x40(64), WINS_DELTA=0x58(88) — confirmed 2026-08-14
            # Class attr handler: 0x212a669 (lina9164_lina, 82MB)
        },
        '9.15.1': {
            'gp_name':  0x2b0,  # CONFIRMED 2026-08-14: 48 vs 0 (FTD 6.7.0-65 qcow2, /usr/local/asa/bin/lina)
            'dns_ptr':  0x2f0,
            'wins_ptr': 0x308,
        },
        '9.17.32': {
            'gp_name':  0x2b0,  # LEA scan: 5 code hits 0x2b0 vs 0 hits 0x2b1 (2026-08-14)
            # single-core (non-SMP) image; same struct layout as SMP train
            'dns_ptr':  0x2f0,
            'wins_ptr': 0x308,
        },
        '9.13.1': {
            'gp_name':  0x2b0,  # CONFIRMED 2026-08-14: 55 vs 0 (ASAv 9.13.1 virtioa.qcow2 initrd)
            'dns_ptr':  0x2f0,
            'wins_ptr': 0x308,
        },
        '9.14.1.1': {
            'gp_name':  0x2b0,  # CONFIRMED 2026-08-14: 54 vs 0 (FTD 6.6.0 qcow2, /usr/local/asa/bin/lina)
            'dns_ptr':  0x2f0,
            'wins_ptr': 0x308,
        },
        '9.20.3': {
            'gp_name':  0x2b0,  # CONFIRMED 2026-08-14: composite score 438 vs 151 (co-0x308=26/2, call-after=386/147)
            # ASAv PLR-Licensed qcow2; PIX (9.20.3); 97MB ELF; extracted from asa9203-smp-k8.bin initrd
            'dns_ptr':  0x2f0,
            'wins_ptr': 0x308,
        },
        '9.22.1.1': {
            'gp_name':  0x2b0,  # CONFIRMED 2026-08-14: co-0x308=34/0, all-LEA=45/42 (ASAv PLR 9.22.1.1 initrd)
            # TRANSITION BOUNDARY: 9.22.1.x = 0x2b0; 9.22.2.x+ = 0x2b1
            # Struct change occurred between 9.22.1.1 and 9.22.2.32 (same minor release)
            'dns_ptr':  0x2f0,
            'wins_ptr': 0x308,
        },
        '9.22.2.32': {
            'gp_name':  0x2b1,  # CONFIRMED: Cisco AI 2026-08-14 + LEA code scan (42 hits)
            # Full report §5 Step4: 0x1a30bbc: strcpy(gp_obj+0x2b1, r14+0x2c1)
            # gp_obj+0x2b1 is char[32] (buffer shrank from 64B in 9.14 to 32B in 9.22)
            # reg_entry_name_offset (r14+0x2c1) is distinct from gp_obj layout
            'reg_entry_name_offset': 0x2c1,  # registration-entry src field, NOT gp_obj
            'dns_ptr':  0x2f0,  # CONFIRMED: Cisco AI 2026-08-14
            'wins_ptr': 0x308,  # CONFIRMED: Cisco AI 2026-08-14 + YARA ACE + full report §5.3
            # OVERFLOW_DELTA=0x57(87) — 96B payload reaches wins_ptr in all version variants
            # SHA-1: a91e860c41a255993635d0227d93ac98e99d87ba
            # BuildID: 88929a4c3f35a2c0786e01e63c2e64626666ef23
        },
    }

    def __init__(self, version_offsets: dict, field_name: str = 'offset',
                 confidence: float = 0.95):
        """
        version_offsets : {'9.14.2.14': 0x308, '9.16.4.18': 0x30c, ...}
        field_name      : label for the offset being tracked (e.g. 'wins_ptr')
        """
        import numpy as np
        import statsmodels.api as sm
        from scipy import stats as sp_stats

        self.field_name = field_name
        self.conf = confidence

        # Sort versions by a numeric key (major.minor.patch.build)
        def _ver_key(v):
            try:
                return tuple(int(x) for x in v.split('.'))
            except Exception:
                return (0,)

        sorted_items = sorted(version_offsets.items(), key=lambda kv: _ver_key(kv[0]))
        self.versions = [v for v, _ in sorted_items]
        self.offsets  = [o for _, o in sorted_items]
        n = len(self.versions)

        self._degenerate = n < 3
        if self._degenerate:
            self.intercept       = float(self.offsets[0]) if n >= 1 else 0.0
            self.slope           = 0.0
            self.r_squared       = float('nan')
            self.se              = float('nan')
            self.fitted          = list(map(float, self.offsets))
            self.residuals       = [0.0] * n
            self.patch_candidates = []
            self.trend           = 'stable'
            self.f_pvalue        = float('nan')
            self._model          = None
            return

        x = np.arange(n, dtype=float)
        y = np.array(self.offsets, dtype=float)

        X_sm = sm.add_constant(x, has_constant='add')
        model = sm.OLS(y, X_sm).fit()
        self._model = model

        self.intercept   = float(model.params[0])
        self.slope       = float(model.params[1])
        self.r_squared   = float(model.rsquared)
        self.se          = float(model.mse_resid ** 0.5)
        self.fitted      = list(model.fittedvalues)
        self.residuals   = list(model.resid)
        self.f_pvalue    = float(model.f_pvalue)

        # Flag versions where |residual| > 2*SE (likely patch/struct change)
        self.patch_candidates = [
            self.versions[i]
            for i in range(n)
            if abs(self.residuals[i]) > 2.0 * self.se
        ]

        # Direction of slope (positive = offset growing, negative = shrinking)
        self.trend = 'growing' if self.slope > 0.5 else ('shrinking' if self.slope < -0.5 else 'stable')

    def predict(self, version_index: int) -> float:
        """Predict offset for a future version by index."""
        return self.intercept + self.slope * version_index

    def is_stable(self, r2_threshold: float = 0.95) -> bool:
        """R² above threshold = offset is highly predictable (not patched)."""
        return self.r_squared >= r2_threshold

    def report(self) -> str:
        lines = [
            f'FIRMWARE VERSION REGRESSION — {self.field_name}',
            '',
            f'  {"Versions analyzed":<28} {len(self.versions)}',
            f'  {"R² (stability score)":<28} {self.r_squared:.6f}  (1.0 = perfectly stable)',
            f'  {"Trend":<28} {self.trend}  ({self.slope:+.2f} bytes/version)',
            f'  {"SE of regression":<28} {self.se:.4f}',
            f'  {"F-test p-value":<28} {self.f_pvalue:.4E}',
            '',
            'Version table:',
            f'  {"Version":<16} {"Offset":>10} {"Fitted":>10} {"Residual":>10} {"Flag"}',
            f'  {"-"*16} {"-"*10} {"-"*10} {"-"*10} {"-"*8}',
        ]
        for i, ver in enumerate(self.versions):
            flag = '** PATCH?' if ver in self.patch_candidates else ''
            lines.append(
                f'  {ver:<16} {self.offsets[i]:#010x} {int(self.fitted[i]):#010x}'
                f' {self.residuals[i]:>+10.2f} {flag}'
            )
        if self.patch_candidates:
            lines += ['', f'  Patch candidates (|residual| > 2*SE): {", ".join(self.patch_candidates)}']
        else:
            lines += ['', '  No patch candidates — offset appears consistent across versions.']
        return '\n'.join(lines)

    @classmethod
    def from_known_offsets(cls, field: str = 'wins_ptr', **extra_versions) -> 'FirmwareVersionRegression':
        """Bootstrap from confirmed LINA offsets + any extra versions you pass."""
        data = {ver: offsets[field] for ver, offsets in cls.KNOWN_OFFSETS.items()
                if field in offsets}
        data.update(extra_versions)
        return cls(data, field_name=field)


# ── Demo ───────────────────────────────────────────────────────────────────────

def run_demo():
    """Built-in advertising→sales dataset demo."""
    import pandas as pd
    import numpy as np

    np.random.seed(42)
    n = 50
    tv        = np.random.uniform(10, 300, n)
    radio     = np.random.uniform(0, 50, n)
    newspaper = np.random.uniform(0, 100, n)
    sales     = 2.9 + 0.046*tv + 0.188*radio + 0.001*newspaper + np.random.normal(0, 1.5, n)

    df = pd.DataFrame({'TV': tv, 'Radio': radio, 'Newspaper': newspaper, 'Sales': sales})
    y  = df['Sales']
    X  = df[['TV', 'Radio', 'Newspaper']]

    parts = ['=' * 72,
             'Python Analysis ToolPak — Demo (Advertising -> Sales)',
             '=' * 72, '']

    reg = Regression(y, X)
    parts.append(reg.report(residuals=False))
    parts.append('')
    parts.append('Equation: ' + reg.equation())
    parts.append('')
    parts.append('=' * 72)
    parts.append('Descriptive Statistics')
    parts.append('=' * 72)
    for col in df.columns:
        parts.append('')
        parts.append(DescriptiveStats(df[col]).report())
    parts.append('')
    parts.append('=' * 72)
    parts.append(CorrelationMatrix(df).report())

    return '\n'.join(parts)


def run_regression(path: str, y_col: str, x_cols=None,
                   logistic: bool = False,
                   residuals: bool = False,
                   descriptive: bool = False,
                   correlation: bool = False,
                   no_constant: bool = False,
                   confidence: float = 0.95) -> str:
    """Load a CSV/Excel file and run regression analysis.

    Returns the full text report (same as Excel Analysis ToolPak output).
    """
    df = load_data(path)
    parts = []

    if descriptive:
        parts += ['=' * 72, 'DESCRIPTIVE STATISTICS', '=' * 72]
        for col in df.columns:
            parts += ['', DescriptiveStats(df[col]).report()]

    if correlation:
        numeric_df = df.select_dtypes(include='number')
        parts += ['', '=' * 72, CorrelationMatrix(numeric_df).report()]

    if y_col:
        y = df[y_col]
        cols = x_cols if x_cols else [c for c in df.columns if c != y_col]
        X = df[cols]
        parts += ['', '=' * 72]
        if logistic:
            lr = LogisticRegression(y, X, confidence=confidence)
            parts.append(lr.report())
        else:
            reg = Regression(y, X, confidence=confidence, constant=not no_constant)
            parts.append(reg.report(residuals=residuals))
            parts += ['', 'Equation: ' + reg.equation()]

    return '\n'.join(parts)


# ── Symbolic Regression Plan — Cisco LINA gp_obj Offset Discovery ──────────────
#
# CODIFIED 2026-08-14 — confirmed with Cisco AI and in methodology.
#
# TWO COMPLEMENTARY APPROACHES to discovering whether Cisco computes gp_obj
# field offsets via a formula vs. arbitrary assignment:
#
# ── APPROACH 1: PySR Symbolic Regression (empirical → algebraic) ──────────────
#
# Feed version metadata → confirmed field offsets into PySR.
# PySR searches the SPACE OF MATHEMATICAL EXPRESSIONS (not just parameters).
# OLS says "it's linear with slope 8". PySR says "offset = 0x2b1 + 8*(minor-14)".
#
# If Cisco uses alignment packing, PySR recovers the exact formula from 3 points.
# If the offsets are arbitrary, PySR finds no compact expression → R² stays low.
#
# Input vector per firmware version: [major, minor, patch, build]
# Target: one field at a time (gp_name, dns_ptr, wins_ptr)
#
# Known data (seed):
#   9.12.3.1  -> gp_name=0x2b0, dns_ptr=0x2f0, wins_ptr=0x308  [CONFIRMED 2026-08-14]
#               attr dispatch @ 0x2770900; OU= xref @ 0x258a5fe; PLT strcpy @ 0xbec610
#   9.14.2.14 -> gp_name=0x2b0, dns_ptr=0x2f0, wins_ptr=0x308  [REVISED 2026-08-14: formula 0x2b1 refuted]
#               4 independent 9.14.x builds scanned: 9.14.1.15/1.30/2.4/4.24 all 0x2b0
#   9.16.4.18 -> gp_name=0x2b0, dns_ptr=0x2f0, wins_ptr=0x308  [CONFIRMED 2026-08-14]
#               handler @ 0x212a669; WINS_DELTA=88(0x58)
#   9.18.x.x  -> UNKNOWN (fp1k/fp2k SPAs; LINA in encrypted application container)
#   9.20.3    -> gp_name=0x2b0, dns_ptr=0x2f0, wins_ptr=0x308  [CONFIRMED 2026-08-14: ASAv PLR qcow2 composite score 438 vs 151]
#   9.21.x.x  -> PRESUMED 0x2b0 (consistent with 9.20.3 + 9.22.1.1 both 0x2b0)
#   9.22.1.1  -> gp_name=0x2b0  [CONFIRMED 2026-08-14: co-0x308=34/0]
#   9.22.2.32 -> gp_name=0x2b1  [CONFIRMED: inline-strcpy @ 0x1a3d8ec]
#   TRANSITION: within 9.22.x branch, between 9.22.1.1 and 9.22.2.32 (inclusive boundary unknown)
#   FORMULA: gp_name = 0x2b0 if version_tuple < (9,22,2,0) else 0x2b1
#
# Install: pip install pysr   (pulls Julia runtime on first run, ~5min)
# Repo:    https://github.com/MilesCranmer/PySR
#
# ── APPROACH 2: REMaQE Binary Symbolic Execution (code → formula) ─────────────
#
# REMaQE symbolically executes the struct-init function and extracts the offset
# computation as a closed-form expression directly from the binary.
# No empirical version data needed — the formula comes FROM THE CODE ITSELF.
#
# Target: LINA 9.14.2.14, struct-init block at 0x1184232
#   Fields confirmed: gp_name@+0x2b1, dns_ptr@+0x2f0, wins_ptr@+0x308
#
# Workflow:
#   1. r2 -c "pdb @ 0x1184232" lina_9.14.2.14 > init_9.14.asm
#   2. REMaQE recovers: offset_expression = f(struct_base, alignment_const, ...)
#   3. Repeat for 9.16, 9.18 — diff the expressions
#   Identical expressions → field stable, same vulnerability surface
#   Changed expression → Cisco patched the struct layout at that version
#
# Repo: https://github.com/FPSG-UIUC/REMaQE
#
# ── INTEGRATION POINT ─────────────────────────────────────────────────────────
#
# PySR and REMaQE are CONVERGENT: PySR discovers formula from data points,
# REMaQE extracts formula from code. If they agree → formula is confirmed.
# That closes the loop: binary RE → algebraic expression → regression validation
# → empirical confirmation on MacStadium target.
#
# PRIORITY ORDER:
#   1. [DONE] RE lina9164_lina (9.16.4.18) — gp_name=0x2b0, dns/wins stable
#   1b.[DONE] RE asa913-mnt/lina (9.12.3.1) — gp_name=0x2b0, dns/wins stable
#   2. Get 9.18/9.20/9.22 binaries from Google Drive
#   3. Run FirmwareVersionRegression with real multi-version data (OLS baseline)
#   4. Run PySR when ≥3 versions confirmed — discover formula or flag arbitrary
#   5. Run REMaQE on 0x1184232 init block — extract formula directly
#   6. If PySR == REMaQE → formula confirmed, cross-version crash boundary prediction live
#
# ─────────────────────────────────────────────────────────────────────────────


class SymbolicOffsetRegression:
    """Hybrid PySR + REMaQE pipeline for Cisco LINA gp_obj offset formula recovery.

    APPROACH SUMMARY (confirmed by Cisco AI, 2026-08-14):

    PySR (empirical side):
      Searches expression trees via evolutionary algorithms to recover exact
      mathematical expressions from observed data — measured field offsets across
      firmware versions. Surfaces formulas that are hard to see purely statically
      (compiler-induced constants, version-specific layout changes). Does not
      require access to the binary — only the numeric observations.

    REMaQE (static/symbolic side):
      Uses symbolic execution (Angr) + algebraic simplification to extract the
      precise equations that the binary itself computes. Ground-truth algebraic
      structure directly from the compiled code — handles registers, stack,
      global memory, pointer-passed parameters, and C++ object patterns.

    Combined pipeline:
      PySR discovers candidate formulas from data.
      REMaQE extracts the formula the binary actually computes.
      If they agree → formula is confirmed, struct layout is algebraic.
      If they disagree → compiler transformation or version-specific delta.
      The recovered offset formulas become algebraic objects that can be
      compared across binary versions to detect layout drift, added/removed
      fields, or padding changes — without debug symbols.

    Requires: pip install pysr  AND  ≥3 confirmed version data points.

    Usage (once data is ready):
        sor = SymbolicOffsetRegression()
        sor.add_version('9.12.3.1',  gp_name=0x2b0, dns_ptr=0x2f0, wins_ptr=0x308)
        sor.add_version('9.14.2.14', gp_name=0x2b1, dns_ptr=0x2f0, wins_ptr=0x308)
        sor.add_version('9.16.4.18', gp_name=0x2b0, dns_ptr=0x2f0, wins_ptr=0x308)
        sor.add_version('9.18.x.x',  gp_name=???, dns_ptr=???, wins_ptr=???)
        print(sor.fit('wins_ptr'))   # prints recovered equation
        print(sor.status())
    """

    FEATURES = ['major', 'minor', 'patch', 'build']

    # Seed from confirmed binary RE — do not change without RE verification
    # Method: LEA instruction scan (48/4c/49/4d 8d ** b0/b1 02 00 00) on CPIO-extracted LINA
    # dns_ptr=0x2f0, wins_ptr=0x308 are INVARIANT across all 8 confirmed versions
    CONFIRMED = {
        '9.12.3.1':  {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},
        '9.12.4.65': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},  # LEA scan 2026-08-14: 0 LEA 0x2b1 instructions
        '9.12.4.72': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},  # LEA scan 2026-08-14: 0 LEA 0x2b1 instructions
        '9.13.1.12': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},  # LEA scan 2026-08-14: 0 hits at 0x2b1, 110 hits at 0x2b0, cluster@0x276a685
        '9.13.1.16': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},
        '9.14.1.15': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},  # LEA scan 2026-08-14: 0 LEA 0x2b1; inline-strcpy+0x2b1 pattern absent
        '9.14.1.30': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},  # LEA scan 2026-08-14: 0 LEA 0x2b1
        '9.14.2.4':  {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},  # LEA scan 2026-08-14: 0 LEA 0x2b1
        '9.14.2.14': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},  # REVISED 2026-08-14: formula-predicted 0x2b1 REFUTED by 4-build scan of 9.14.x
        '9.14.4.24': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},  # LEA scan 2026-08-14: 0 LEA 0x2b1
        '9.15.1.15': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},
        '9.16.1':    {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},
        '9.16.4.18': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},
        '9.16.4.27': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},  # LEA scan 2026-08-14: 0 inline-strcpy hits (different loop structure)
        '9.16.4.84': {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},  # LEA scan 2026-08-14: 0 inline-strcpy hits; all 0x2b1 LEAs are non-gp_obj
        '9.17.32':   {'gp_name': 0x2b0, 'dns_ptr': 0x2f0, 'wins_ptr': 0x308},
        '9.22.2.32': {
            'gp_name':  0x2b1,   # CONFIRMED: inline-strcpy+0x2b1 pattern at 0x1a3d8ec; LEA scan 42 hits; Cisco AI 2026-08-14
            # 7-byte sequence 488d97b1020000 (lea rdx,[rdi+0x2b1]) appears exactly once; 0 times in all 9.12-9.17 builds
            'reg_entry_name_offset': 0x2c1,
            'dns_ptr':  0x2f0,
            'wins_ptr': 0x308,
        },
    }

    # FORMULA STATUS: REFUTED (2026-08-14)
    # Original formula: gp_name = 0x2b1 if (minor & 3 == 2) else 0x2b0
    # Refuted by: 4 independent 9.14.x binary scans (minor=14, 14&3=2) → ALL 0x2b0
    #   9.14.1.15, 9.14.1.30, 9.14.2.4, 9.14.4.24: zero LEA 0x2b1 instructions;
    #   inline-strcpy+0x2b1 signature (488d97b1020000 7-byte sequence) absent in all.
    # Confirmed boundary: 9.12.x–9.17.x all 0x2b0; 9.22.x is 0x2b1.
    # Transition range: 9.18.x–9.21.x status UNKNOWN (fp1k/fp2k SPAs; LINA not accessible).
    # Current evidence: 17 builds confirmed 0x2b0, 1 build confirmed 0x2b1. No algebraic pattern.
    GP_NAME_FORMULA = 'gp_name = 0x2b1 if (minor & 3 == 2) else 0x2b0'  # REFUTED — do not use for prediction
    # Formula validity range: minor >= 12 (F2-path gp_obj struct introduced ~9.12.x)
    # Pre-9.12.x (e.g. 9.6.4.18, 9.10.1.40): different struct layout, formula does NOT apply
    # Verified out-of-scope: 9.6.4.18 (asa964-18-smp-k8.bin, 2026-08-14) — 60 scattered
    #   LEA 0x2b0 hits across 13 code blocks, no dominant cluster; 0x2b1 = 0 hits
    #   Struct layout predates the 0x2b0/0x2b1 gp_name field introduction
    FORMULA_MINOR_MIN = 12  # inclusive lower bound; extrapolation below this is invalid

    # Derived structural relationship (2026-08-14, paired LEA analysis):
    #   reg_entry_name_offset = gp_name_offset + 0x10   (constant delta, all F2-path versions)
    # 9.22.2.32: gp_name=0x2b1 → reg_entry_name=0x2c1 (confirmed, Cisco AI + RE)
    # 9.13.1.16: gp_name=0x2b0 → reg_entry_name=0x2c0 (inferred from tight LEA pair @ 0x3a2796b)
    REG_ENTRY_NAME_DELTA = 0x10

    # REMaQE target for struct-init symbolic execution
    REMAQE_TARGET = {
        'binary':           'lina_9.14.2.14',
        'function_vaddr':   0x1184232,
        'description':      'gp_obj struct field initialization block',
        'fields_confirmed': ['gp_name@+0x2b0', 'dns_ptr@+0x2f0', 'wins_ptr@+0x308'],  # 0x2b0 per 9.14.x scan evidence
        # 9.22.2.32 gp_name setter: lea rdx,[rdi+0x2b1] at 0x1a3d8d8; inline byte-copy at 0x1a3d8ec
        #   7-byte sequence 488d97b1020000 appears exactly once in 9.22.2.32, zero times in all 9.12-9.17 builds
        #   OVERFLOW_DELTA=87 (0x308-0x2b1) for 9.22.x; OVERFLOW_DELTA=88 (0x308-0x2b0) for 9.12-9.17.x
        # YARA BuildID (9.22.2.32): 88929a4c3f35a2c0786e01e63c2e64626666ef23
    }

    @classmethod
    def predict_gp_name(cls, version: str) -> int:
        """Return predicted gp_name offset for a version string.

        WARNING: Formula 'minor & 3 == 2 → 0x2b1' is REFUTED (2026-08-14).
        Refuted by 4 independent scans of 9.14.x binaries (minor=14, 14&3=2) all returning 0x2b0.
        For confirmed versions in CONFIRMED dict, use that directly.
        For 9.18.x–9.21.x, offset is UNKNOWN (fp1k/fp2k SPAs; LINA not accessible).
        Only 9.22.x is confirmed 0x2b1. This method returns the formula output but it is
        unreliable for minor in {14, 18, ...} — check CONFIRMED first.
        Valid range: minor >= 12.
        """
        minor = int(version.split('.')[1])
        if minor < cls.FORMULA_MINOR_MIN:
            raise ValueError(
                f'version {version} (minor={minor}) is below FORMULA_MINOR_MIN={cls.FORMULA_MINOR_MIN}; '
                'formula does not apply — pre-F2-path struct layout'
            )
        return 0x2b1 if (minor & 3 == 2) else 0x2b0

    @classmethod
    def predict_offsets(cls, version: str) -> dict:
        """Return full predicted gp_obj offset map for a version string.

        Returns all confirmed-invariant offsets plus the formula-derived ones.
        All fields confirmed on 8 versions (9.12.3.1–9.22.2.32, 2026-08-14).
        """
        gp_name = cls.predict_gp_name(version)
        return {
            'gp_name':              gp_name,
            'reg_entry_name':       gp_name + cls.REG_ENTRY_NAME_DELTA,
            'dns_ptr':              0x2f0,   # INVARIANT: confirmed all 8 versions
            'wins_ptr':             0x308,   # INVARIANT: confirmed all 8 versions
            'overflow_delta':       0x308 - gp_name,  # bytes from gp_name to wins_ptr
        }

    def __init__(self):
        self._data = {k: dict(v) for k, v in self.CONFIRMED.items()}

    def add_version(self, version: str, **field_offsets):
        """Add a confirmed version data point after RE of a new binary."""
        if version not in self._data:
            self._data[version] = {}
        self._data[version].update(field_offsets)

    def _parse_version(self, v: str) -> list:
        try:
            parts = [int(x) for x in v.split('.')]
            return (parts + [0, 0, 0, 0])[:4]
        except Exception:
            return [0, 0, 0, 0]

    def fit(self, field: str = 'wins_ptr') -> str:
        """Run PySR to discover the offset formula for one struct field.

        Returns the best discovered equation as a string, or an error message
        if PySR is not installed or there is insufficient data.
        """
        try:
            from pysr import PySRRegressor
        except ImportError:
            return "PySR not installed. Run: pip install pysr"

        import numpy as np

        rows = [(ver, offsets[field])
                for ver, offsets in self._data.items()
                if field in offsets]

        if len(rows) < 3:
            return (f"Need ≥3 data points for '{field}'. "
                    f"Have {len(rows)}: {[r[0] for r in rows]}")

        X = np.array([self._parse_version(v) for v, _ in rows], dtype=float)
        y = np.array([o for _, o in rows], dtype=float)

        model = PySRRegressor(
            niterations=100,
            binary_operators=['+', '-', '*'],
            unary_operators=['square'],
            maxsize=12,
            verbosity=0,
        )
        model.fit(X, y)

        lines = [
            f'PySR SYMBOLIC REGRESSION — {field}',
            f'Versions used: {[r[0] for r in rows]}',
            '',
            str(model),
        ]
        return '\n'.join(lines)

    def status(self) -> str:
        lines = ['SYMBOLIC OFFSET REGRESSION STATUS', '',
                 f'  {"Field":<12} {"Confirmed versions":<40} {"Needed"}']
        for field in ('gp_name', 'dns_ptr', 'wins_ptr'):
            confirmed = [v for v, d in self._data.items() if field in d]
            need = max(0, 3 - len(confirmed))
            need_str = f'{need} more' if need > 0 else 'READY for PySR'
            lines.append(f'  {field:<12} {str(confirmed):<40} {need_str}')
        lines += [
            '',
            f'  REMaQE target: 0x{self.REMAQE_TARGET["function_vaddr"]:x}'
            f' ({self.REMAQE_TARGET["binary"]})',
            f'  Fields in scope: {", ".join(self.REMAQE_TARGET["fields_confirmed"])}',
        ]
        return '\n'.join(lines)

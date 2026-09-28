"""Probability metrics for the dashboard's PDF reports.

Stdlib only (no numpy/scipy, no Qt) so the maths is unit-testable without the
app's venv. Every helper returns plain numbers; ``stats_table_html`` renders a
small "what this number means" table the report modules drop in next to the
statistic it qualifies.

What the reports use:

  * ``wilson``      -- a rate k/n (e.g. "12 of 12 exploits diverted") with a
                       95% Wilson score interval. Unlike the textbook
                       p +/- 1.96*sqrt(p(1-p)/n) it stays inside 0..100% and is
                       sensible for small n and for 0% / 100%.
  * ``summarize``   -- mean, SD, median, p95, and a 95% Student-t confidence
                       interval for the mean. For time series (CPU/RAM sampled
                       every 0.25-2s) neighbouring samples are correlated, so
                       ``autocorr=True`` shrinks n to an effective sample size
                       n_eff = n * (1 - r1) / (1 + r1) (r1 = lag-1
                       autocorrelation) before computing the interval.
  * ``exceedance``  -- the share of a recorded window spent at or above a
                       level, i.e. the chance a random moment of it was that busy.
  * ``welch``       -- Welch's two-sample t-test: is the "after" mean really
                       different from the "before" mean, or could the gap be
                       noise? Returns a two-sided p-value.
  * ``trend``       -- least-squares slope with a 95% CI and the p-value for
                       "slope = 0" (does the score really ratchet up?).
  * ``fit_decay``   -- fits score = peak * 0.5^(t / half_life) by linear
                       regression on log2(score), giving the measured
                       half-life with a 95% CI and R^2 to set beside the
                       configured one.
"""
from __future__ import annotations

import html as _html
import math
from dataclasses import dataclass

CONFIDENCE = 0.95
Z95 = 1.959963984540054


# ---- distributions -----------------------------------------------------------

def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the regularized incomplete beta (Lentz)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-12:
            break
    return h


def _betainc(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_front = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(ln_front) * _betacf(a, b, x) / a
    return 1.0 - math.exp(ln_front) * _betacf(b, a, 1.0 - x) / b


def t_sf2(t: float, df: float) -> float:
    """Two-sided tail probability P(|T| >= |t|) for Student's t with ``df``."""
    if df <= 0 or math.isnan(t):
        return float("nan")
    if math.isinf(t):
        return 0.0
    return _betainc(df / 2.0, 0.5, df / (df + t * t))


def t_ppf(p: float, df: float) -> float:
    """Quantile of Student's t (bisection on the CDF; p in (0, 1))."""
    if not 0.0 < p < 1.0:
        raise ValueError("p must be in (0, 1)")
    if p == 0.5:
        return 0.0
    upper = p > 0.5
    tail = 2.0 * (1.0 - p if upper else p)  # two-sided tail mass to match
    lo, hi = 0.0, 1.0
    while t_sf2(hi, df) > tail:
        hi *= 2.0
        if hi > 1e8:
            break
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if t_sf2(mid, df) > tail:
            lo = mid
        else:
            hi = mid
    q = (lo + hi) / 2.0
    return q if upper else -q


def t_crit(df: float, confidence: float = CONFIDENCE) -> float:
    """Two-sided critical value, e.g. 2.262 for df=9 at 95%."""
    return t_ppf(0.5 + confidence / 2.0, df)


# ---- rates -------------------------------------------------------------------

@dataclass
class Rate:
    k: int
    n: int
    p: float
    lo: float
    hi: float


def wilson(k: int, n: int, z: float = Z95) -> Rate | None:
    """k successes out of n, with a Wilson score interval. None when n == 0."""
    if n <= 0:
        return None
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    lo, hi = max(0.0, centre - half), min(1.0, centre + half)
    # Exact endpoints at 0% / 100% (avoid 1e-17 rounding noise).
    if k == 0:
        lo = 0.0
    if k == n:
        hi = 1.0
    return Rate(k, n, p, lo, hi)


# ---- descriptive + CI of the mean -------------------------------------------

def lag1_autocorr(values: list[float]) -> float:
    n = len(values)
    if n < 3:
        return 0.0
    m = sum(values) / n
    den = sum((v - m) ** 2 for v in values)
    if den == 0:
        return 0.0
    num = sum((values[i] - m) * (values[i + 1] - m) for i in range(n - 1))
    return num / den


def percentile(values: list[float], q: float) -> float:
    """Linear-interpolated percentile, q in [0, 100]."""
    xs = sorted(values)
    if not xs:
        return float("nan")
    pos = (len(xs) - 1) * q / 100.0
    i = int(math.floor(pos))
    j = min(i + 1, len(xs) - 1)
    return xs[i] + (xs[j] - xs[i]) * (pos - i)


@dataclass
class Summary:
    n: int
    mean: float
    sd: float
    median: float
    p95: float
    min: float
    max: float
    lo: float | None       # CI of the mean; None when it can't be computed
    hi: float | None
    n_eff: float           # effective sample size the CI was based on


def effective_n(values: list[float]) -> float:
    """n shrunk for lag-1 autocorrelation: n * (1 - r1) / (1 + r1), at least 2."""
    n = len(values)
    if n < 3:
        return float(n)
    r1 = max(0.0, min(0.99, lag1_autocorr(values)))
    return max(2.0, min(float(n), n * (1 - r1) / (1 + r1)))


def summarize(values: list[float], autocorr: bool = False,
              confidence: float = CONFIDENCE, floor: float | None = None) -> Summary | None:
    """``floor`` clips the CI's lower end for quantities that can't go below it
    (CPU %, memory), so a wide interval never reads as "-15% CPU"."""
    xs = [float(v) for v in values if v is not None]
    n = len(xs)
    if n == 0:
        return None
    mean = sum(xs) / n
    sd = math.sqrt(sum((v - mean) ** 2 for v in xs) / (n - 1)) if n > 1 else 0.0
    n_eff = effective_n(xs) if autocorr else float(n)
    lo = hi = None
    if n >= 2:
        if sd == 0:
            lo = hi = mean
        else:
            half = t_crit(n_eff - 1, confidence) * sd / math.sqrt(n_eff)
            lo, hi = mean - half, mean + half
            if floor is not None:
                lo = max(floor, lo)
    return Summary(n, mean, sd, percentile(xs, 50), percentile(xs, 95),
                   min(xs), max(xs), lo, hi, n_eff)


def exceedance(values: list[float], level: float) -> float | None:
    """Fraction of samples >= level (empirical P(X >= level)); None if empty."""
    xs = [v for v in values if v is not None]
    if not xs:
        return None
    return sum(1 for v in xs if v >= level) / len(xs)


# ---- comparisons -------------------------------------------------------------

@dataclass
class Comparison:
    mean_a: float
    mean_b: float
    diff: float            # mean_b - mean_a
    t: float
    df: float
    p: float               # two-sided p-value


def welch(a: list[float], b: list[float], autocorr: bool = False) -> Comparison | None:
    """Welch's t-test for mean(b) != mean(a). None if either side has < 2 values.
    With ``autocorr`` each side counts as its effective sample size (same
    correction as ``summarize``), so time series aren't over-confident."""
    a = [float(v) for v in a]
    b = [float(v) for v in b]
    if len(a) < 2 or len(b) < 2:
        return None
    ma, mb = sum(a) / len(a), sum(b) / len(b)
    va = sum((v - ma) ** 2 for v in a) / (len(a) - 1)
    vb = sum((v - mb) ** 2 for v in b) / (len(b) - 1)
    na = effective_n(a) if autocorr else len(a)
    nb = effective_n(b) if autocorr else len(b)
    se2 = va / na + vb / nb
    diff = mb - ma
    if se2 == 0:
        return Comparison(ma, mb, diff, 0.0 if diff == 0 else math.inf,
                          float(na + nb - 2), 1.0 if diff == 0 else 0.0)
    t = diff / math.sqrt(se2)
    df = se2 ** 2 / ((va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1))
    return Comparison(ma, mb, diff, t, df, t_sf2(t, df))


@dataclass
class Trend:
    n: int
    slope: float
    lo: float
    hi: float
    p: float               # H0: slope == 0
    r2: float


def trend(xs: list[float], ys: list[float]) -> Trend | None:
    """Ordinary least squares y = a + b*x; CI and p-value for b. Needs n >= 3."""
    pts = [(float(x), float(y)) for x, y in zip(xs, ys) if y is not None]
    n = len(pts)
    if n < 3:
        return None
    mx = sum(x for x, _ in pts) / n
    my = sum(y for _, y in pts) / n
    sxx = sum((x - mx) ** 2 for x, _ in pts)
    if sxx == 0:
        return None
    sxy = sum((x - mx) * (y - my) for x, y in pts)
    syy = sum((y - my) ** 2 for _, y in pts)
    b = sxy / sxx
    a = my - b * mx
    sse = sum((y - (a + b * x)) ** 2 for x, y in pts)
    r2 = 1.0 - sse / syy if syy > 0 else 1.0
    df = n - 2
    se = math.sqrt(sse / df / sxx)
    if se == 0:
        return Trend(n, b, b, b, 0.0 if b != 0 else 1.0, r2)
    half = t_crit(df) * se
    return Trend(n, b, b - half, b + half, t_sf2(b / se, df), r2)


@dataclass
class DecayFit:
    n: int
    half_life: float | None        # None when the fit shows no decay
    lo: float | None               # 95% CI of the half-life (None = unbounded)
    hi: float | None
    r2: float
    rmse_vs_model: float | None    # vs the configured model curve, score points


def fit_decay(samples: list[tuple[float, float]], model_half_life: float | None = None,
              peak: float | None = None) -> DecayFit | None:
    """Fit score = S0 * 0.5^(t / h) to (t, score) samples.

    log2(score) = log2(S0) - t / h, so the slope b of a straight-line fit on
    log2(score) is -1/h and the CI of h comes from inverting the slope's CI.
    Zero scores are dropped (log undefined). ``rmse_vs_model`` compares the
    raw samples to peak * 0.5^(t / model_half_life) (or the flat peak when
    model_half_life is None, i.e. decay off)."""
    pts = [(float(t), float(s)) for t, s in samples if s is not None and s > 0]
    if len(pts) < 3:
        return None
    tr = trend([t for t, _ in pts], [math.log2(s) for _, s in pts])
    if tr is None:
        return None

    def inv(b: float) -> float | None:
        return -1.0 / b if b < 0 else None

    h = inv(tr.slope)
    # Slope CI [lo, hi] maps to half-life [inv(lo), inv(hi)]; a slope CI that
    # reaches 0 or above means the data can't rule out "no decay" -> no upper bound.
    h_lo = inv(tr.lo)
    h_hi = inv(tr.hi) if tr.hi < 0 else None
    rmse = None
    if peak is not None:
        errs = []
        for t, s in samples:
            if s is None:
                continue
            model = peak * (0.5 ** (t / model_half_life)) if model_half_life else peak
            errs.append((float(s) - model) ** 2)
        if errs:
            rmse = math.sqrt(sum(errs) / len(errs))
    return DecayFit(len(pts), h, h_lo, h_hi, tr.r2, rmse)


# ---- formatting --------------------------------------------------------------

def fmt_pct(x: float, digits: int = 0) -> str:
    return f"{x * 100:.{digits}f}%"


def fmt_rate(r: Rate | None) -> str:
    """'12/12 = 100% (95% CI 76-100%)'."""
    if r is None:
        return "n/a (no data)"
    return (f"{r.k}/{r.n} = {fmt_pct(r.p)} "
            f"(95% CI {r.lo * 100:.0f}&ndash;{r.hi * 100:.0f}%)")


def fmt_p(p: float | None) -> str:
    """APA-ish p-value: 'p = 0.034', 'p < 0.001'."""
    if p is None or math.isnan(p):
        return "p = n/a"
    if p < 0.001:
        return "p &lt; 0.001"
    return f"p = {p:.3f}"


def p_meaning(p: float | None, alpha: float = 0.05) -> str:
    if p is None or math.isnan(p):
        return "not enough samples to test"
    if p < alpha:
        return "unlikely to be chance (significant at 5%)"
    return "could plausibly be chance (not significant at 5%)"


def fmt_mean_ci(s: Summary | None, unit: str = "", digits: int = 1) -> str:
    """'42.3 (95% CI 38.1-46.5)'."""
    if s is None:
        return "n/a"
    base = f"{s.mean:.{digits}f}{unit}"
    if s.lo is None:
        return base + " (one sample, no CI)"
    return (f"{base} (95% CI {s.lo:.{digits}f}&ndash;{s.hi:.{digits}f}{unit})")


def stats_table_html(rows: list[tuple[str, str, str]], title: str = "Probability metrics") -> str:
    """A compact 3-column table: statistic | value (with CI / p) | what it means.
    Every cell is trusted HTML written by the report code (labels may carry
    entities like &ge;), so pass nothing user- or network-derived in here."""
    if not rows:
        return ""
    body = "".join(
        '<tr>'
        f'<td style="color:#333;">{label}</td>'
        f'<td style="color:#111;"><b>{value}</b></td>'
        f'<td style="color:#666;">{meaning}</td>'
        '</tr>'
        for label, value, meaning in rows)
    return ('<table width="100%" cellspacing="0" cellpadding="3" border="1" '
            'style="border-collapse:collapse; font-size:9pt; margin-top:4px;">'
            f'<tr style="background-color:#eef3f8;"><th align="left" colspan="3">'
            f'{_html.escape(title)}</th></tr>' + body + '</table>')


GLOSSARY_HTML = (
    '<p style="color:#555; font-size:9pt;"><b>Reading the probability metrics.</b> '
    'A <b>95% confidence interval (CI)</b> is the range the true value would fall in '
    '95 times out of 100 if the measurement were repeated: a wide interval means few '
    'or noisy samples, a narrow one means the figure is well pinned down. A '
    '<b>p-value</b> is the probability of seeing a difference at least this large if '
    'there were really no effect; below 0.05 it is conventionally called '
    '<i>significant</i>, i.e. unlikely to be chance. Rates use the Wilson interval, '
    'which stays within 0&ndash;100% even for small samples or 0% / 100% results. '
    'Where a mean over a time series (CPU, memory) has a CI, it uses an effective '
    'sample size that discounts correlated neighbouring samples, so it is not '
    'over-confident. <b>P(&ge;x)</b> is the share of a recording spent at or above '
    '<i>x</i>: the chance that a randomly picked moment was that busy. <b>SD</b> '
    '(standard deviation) is the typical distance of a value from the mean.</p>')

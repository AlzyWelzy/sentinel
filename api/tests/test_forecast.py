"""Trend projection for the Forecast tab."""

from app.services.forecast import project


def test_rising_series_reaches_limit():
    # 1 point per hour for 3 days, rising 10 points a day from 40%.
    hist = [[h * 3600, 40 + h * 10 / 24] for h in range(72)]
    p = project(hist, horizon=7 * 86400, step=3600)
    assert p is not None
    assert abs(p.slope_per_day - 10) < 0.01
    # 70% now; reaches 90% about two days after the last point.
    assert abs(p.reaches_at - (71 * 3600 + 2 * 86400)) <= 3600
    assert p.points[0][1] == round(40 + 71 * 10 / 24, 2)


def test_flat_series_with_peaks_uses_the_band():
    hist = [[h * 3600, 95 if h % 24 == 12 else 50] for h in range(96)]
    p = project(hist, horizon=86400, step=3600, limit=99)
    assert p is not None and abs(p.slope_per_day) < 1
    assert p.reaches_at is None  # peaks are 95, below 99
    assert max(v for _, v in p.upper) > 50


def test_too_little_history():
    assert project([[0, 1], [3600, 2]], horizon=86400, step=3600) is None

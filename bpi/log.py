"""Where the BPI Challenge 2019 log is, and how to read it."""

import pandas as pd

from protocol.loader import PROJECT_ROOT

BPI_FILE = PROJECT_ROOT / "data" / "bpi2019" / "BPI_Challenge_2019.csv.gz"


def load_bpi(columns):
    """Read the full BPI log, keeping only the columns we need."""
    return pd.read_csv(BPI_FILE, usecols=columns)
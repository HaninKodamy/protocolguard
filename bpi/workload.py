"""A realistic workload: real purchases sampled from the BPI Challenge 2019 log."""

from bpi.log import load_bpi

ORDER_ACTIVITY = "Create Purchase Order Item"


def sample_purchases(n=1000, seed=42):
    """Return (quotes, purchases) for n real purchase items, sampled reproducibly."""
    log = load_bpi(["case concept:name", "case Vendor", "case Sub spend area text",
                    "event concept:name", "event Cumulative net worth (EUR)"])
    orders = log[log["event concept:name"] == ORDER_ACTIVITY]
    if orders.empty:
        raise ValueError(f"No '{ORDER_ACTIVITY}' events found in the BPI log")
    orders = orders.drop_duplicates("case concept:name").dropna()
    orders = orders[orders["event Cumulative net worth (EUR)"] > 0]
    sample = orders.sample(n=n, random_state=seed)

    quotes = {}
    purchases = []
    for _, row in sample.iterrows():
        case_id = row["case concept:name"]
        vendor_id = row["case Vendor"]
        item = row["case Sub spend area text"]
        amount = float(row["event Cumulative net worth (EUR)"])
        quotes[case_id] = [{"vendor_id": vendor_id, "amount": amount, "text": f"Offer for {item}."}]
        purchases.append((case_id, item, 1, amount))
    return quotes, purchases
"""Explore the BPI Challenge 2019 event log and check it is complete."""

from bpi.log import load_bpi

if __name__ == "__main__":
    log = load_bpi(["case concept:name", "case Vendor", "case Name", "event concept:name"])

    print("Events:    ", len(log))
    print("Cases:     ", log["case concept:name"].nunique())
    print("Activities:", log["event concept:name"].nunique())
    print("Vendors:   ", log["case Vendor"].nunique())
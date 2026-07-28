"""External system integrations (ticketing, ITSM).

Kept separate from scanr.core: these talk to systems ScanR does not control, so
they fail differently (auth expiry, rate limits, schema drift) and must never be
able to fail a scan.
"""

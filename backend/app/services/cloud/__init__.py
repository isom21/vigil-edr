"""Cloud telemetry ingestion + anomaly detection (Phase 4 #4.2).

Submodules:

  * ``cloudtrail`` — AWS CloudTrail S3 bucket listing/fetching + log
    record parsing into a uniform event shape.
  * ``iam_anomaly`` — per-(source, principal) baseline + four
    detectors that fire synthetic Vigil alerts.
"""

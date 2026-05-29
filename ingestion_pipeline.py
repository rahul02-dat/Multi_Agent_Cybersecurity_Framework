#!/usr/bin/env python3
"""
================================================================================
 ingestion_pipeline.py
 Unified Security Log Ingestion Pipeline — Phase 1: Data Contracts & Ingestion
================================================================================
 System  : Autonomous Multi-Agent Threat Intelligence System
 Version : 1.0.0

 Supported Datasets
 ──────────────────
   • CIC-IDS2018      Macro network attack flows (DDoS, Brute Force, PortScan…)
                      https://www.unb.ca/cic/datasets/ids-2018.html
   • CIC-DoHBrw-2020  DNS-over-HTTPS tunneling / covert channel anomalies
                      https://www.unb.ca/cic/datasets/dohbrw-2020.html

 Architecture Overview
 ─────────────────────
   CSV files (GB-scale)
       │
       ▼  pd.read_csv(chunksize=N)           ← memory-safe lazy streaming
   [ Raw Chunk: pd.DataFrame ]
       │
       ▼  _process_chunk()
       ├─ [Stage 1] Strip column-header whitespace    ← fixes CIC hidden-space headers
       ├─ [Stage 2] Replace ±inf → NaN → 0 (numeric)  ← bulk per-column sanitization
       ├─ [Stage 3] parse_ids2018_row / parse_doh2020_row  ← per-row translation
       └─ [Stage 4] UnifiedSecurityLog(**mapped)           ← Pydantic v2 validation
               │
               ├── PASS → appended to output list
               └── FAIL → exact error logged to stderr; row dropped; loop continues

 Requirements
 ────────────
   pip install "pandas>=1.3.0" "pydantic>=2.0.0"
================================================================================
"""

from __future__ import annotations  # PEP 563: postponed annotation evaluation

import csv
import math
import sys
import logging
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Literal, Optional

import pandas as pd
import pydantic
from pydantic import BaseModel, ConfigDict, Field


# ── Library version guards ────────────────────────────────────────────────────
# Fail immediately with an actionable message rather than a cryptic AttributeError
# deep inside the application later.
if int(pydantic.VERSION.split(".")[0]) < 2:
    raise RuntimeError(
        f"Pydantic ≥ 2.0 required (found {pydantic.VERSION}). "
        "Upgrade: pip install 'pydantic>=2.0.0'"
    )

_pd_ver = tuple(int(x) for x in pd.__version__.split(".")[:2])
if _pd_ver < (1, 3):
    raise RuntimeError(
        f"pandas ≥ 1.3.0 required (found {pd.__version__}). "
        "Upgrade: pip install 'pandas>=1.3.0'"
    )

# ── Structured logging — all diagnostics go to stderr, never stdout ───────────
# stdout stays clean for piped JSON output; stderr carries operational telemetry.
logging.basicConfig(
    stream=sys.stderr,
    level=logging.WARNING,      # Change to logging.DEBUG for verbose chunk tracing
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("threat_intel.ingestion")

# ── Module-level constants ────────────────────────────────────────────────────
CHUNK_SIZE: int = 10_000  # Rows per streaming chunk.
                           # Rule of thumb: target ~50 MB/chunk.
                           # 10 000 rows × ~5 KB/row ≈ 50 MB. Tune per env.

# IANA transport-layer protocol number → canonical name.
# Only TCP and UDP are first-class citizens in our contract; everything else
# maps to "Unknown" so the field always satisfies the Literal constraint.
# Source: https://www.iana.org/assignments/protocol-numbers/
IDS2018_PROTO_MAP: dict[int, str] = {
    0:   "Unknown",   # HOPOPT / undefined
    1:   "Unknown",   # ICMP  (not TCP/UDP; maps to Unknown)
    6:   "TCP",
    17:  "UDP",
    41:  "Unknown",   # IPv6-in-IPv4 encapsulation
    58:  "Unknown",   # ICMPv6
    132: "Unknown",   # SCTP
}

# Type alias — used in function signatures for readability and mypy narrowing.
DatasetType = Literal["IDS2018", "DoH2020"]


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 1 — UNIFIED DATA CONTRACT (Pydantic v2)                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class UnifiedSecurityLog(BaseModel):
    """
    Canonical, immutable data contract for all ingested security network flows.

    This model is the single source of truth consumed by every downstream
    system: feature pipelines, ML inference engines, SIEM alert rules, and
    the data lake write path.

    Design Decisions
    ─────────────────
    • `extra="forbid"` — mapper bugs (extra/misspelled keys) surface immediately
      at development time as ValidationErrors rather than silently being ignored.
    • `str_strip_whitespace=True` — handles any residual leading/trailing spaces
      that survived earlier normalization.
    • `strict=False` — allows safe numeric coercions (int 0 → float 0.0) while
      still rejecting structurally invalid values (e.g., "abc" for a port).

    Field Invariants (guaranteed post-validation by Pydantic constraints)
    ─────────────────────────────────────────────────────────────────────
    • flow_duration      always in microseconds (μs);  ge=0
    • source_port        always in [0, 65535]
    • destination_port   always in [0, 65535]
    • bytes_per_second   always ≥ 0.0
    • packets_per_second always ≥ 0.0
    • protocol           always one of "TCP" | "UDP" | "Unknown"
    • ground_truth_label always a non-empty string (min_length=1)
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,  # Strip residual spaces from all string values
        extra="forbid",             # Fail loudly on unexpected mapper output keys
        strict=False,               # Allow safe numeric coercions only
    )

    source_dataset: Literal["IDS2018", "DoH2020"] = Field(
        description="Originating dataset identifier — used for lineage tracking."
    )
    timestamp: str = Field(
        description="ISO 8601 timestamp string, UTC-normalized where the source "
                    "format permits."
    )
    protocol: Literal["TCP", "UDP", "Unknown"] = Field(
        description="Transport-layer protocol. Mapped from raw integer codes or "
                    "inferred from context (e.g., DoH always uses TCP)."
    )
    flow_duration: int = Field(
        ge=0,
        description="Bidirectional flow lifetime in microseconds (μs). "
                    "All source duration units are converted to this standard."
    )
    source_port: int = Field(
        ge=0, le=65535,
        description="Layer-4 source port number in the valid range [0, 65535]."
    )
    destination_port: int = Field(
        ge=0, le=65535,
        description="Layer-4 destination port number in the valid range [0, 65535]."
    )
    bytes_per_second: float = Field(
        ge=0.0,
        description="Bidirectional flow throughput in bytes/second."
    )
    packets_per_second: float = Field(
        ge=0.0,
        description="Bidirectional flow rate in packets/second."
    )
    ground_truth_label: str = Field(
        min_length=1,
        description="Human-readable attack or benign classification from the "
                    "source dataset labelling scheme."
    )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 2 — SANITIZATION UTILITIES                                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _is_float_sentinel(value: object) -> bool:
    """
    Return True if *value* is a floating-point sentinel that is invalid in JSON
    and would cause a Pydantic ValidationError: NaN, +inf, or -inf.
    """
    try:
        f = float(value)  # type: ignore[arg-type]
        return math.isnan(f) or math.isinf(f)
    except (TypeError, ValueError):
        return False


def sanitize_float(value: object, default: float = 0.0) -> float:
    """
    Coerce *value* to a finite Python float.

    Safely handles: None, NaN, ±inf, empty string, non-numeric strings,
    and any type for which float() raises TypeError or ValueError.
    All unrepresentable inputs collapse to *default* (0.0 by contract).

    This is the authoritative numeric coercion function used throughout.
    All other numeric helpers (sanitize_int, clamp_port) delegate to this.
    """
    if value is None:
        return default
    try:
        f = float(value)  # type: ignore[arg-type]
        return default if (math.isnan(f) or math.isinf(f)) else f
    except (TypeError, ValueError):
        return default


def sanitize_int(value: object, default: int = 0) -> int:
    """
    Coerce *value* to a Python int via safe float parsing, then truncation.
    Delegates all edge-case handling to sanitize_float — never duplicates logic.
    """
    return int(sanitize_float(value, float(default)))


def sanitize_str(value: object, default: str = "UNKNOWN") -> str:
    """
    Coerce *value* to a non-empty, stripped Python str.

    Critical correctness: float NaN / ±inf yield *default*, NOT the strings
    "nan" / "inf". pandas represents missing string cells as float NaN, so
    this case is extremely common in real CIC CSVs.
    """
    if value is None:
        return default
    if _is_float_sentinel(value):
        return default
    result = str(value).strip()
    return result if result else default


def clamp_port(value: object) -> int:
    """
    Convert *value* to a valid TCP/UDP port number in [0, 65535].

    Values outside the valid range are *clamped* (not rejected) to preserve
    row utility. A port of 70000 is almost certainly a float precision artefact;
    discarding the entire row over it would lose all other valid signal.
    """
    return max(0, min(65535, sanitize_int(value, 0)))


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 3 — DATASET-SPECIFIC TRANSLATION LAYERS                           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def parse_ids2018_row(row: dict) -> dict:
    """
    Translate one CIC-IDS2018 flow record into a UnifiedSecurityLog field dict.

    ┌─────────────────────────────────────────────────────────────────────────┐
    │ CIC-IDS2018 Quirk Register — all dataset-specific issues resolved here  │
    ├─────────────────────────────────────────────────────────────────────────┤
    │ Q1. Column headers contain leading/trailing spaces in the raw CSV.      │
    │     E.g., " Dst Port " instead of "Dst Port".                           │
    │     → Stripped at chunk level (Stage 1 of _process_chunk) before this  │
    │       function is ever called. Belt-and-suspenders: we also try         │
    │       alternative spellings via chained .get() fallbacks.               │
    │                                                                         │
    │ Q2. `Protocol` is an IANA integer code, NOT a string.                  │
    │     6 = TCP, 17 = UDP, everything else = "Unknown" per our contract.   │
    │     → Mapped through IDS2018_PROTO_MAP at the module level.             │
    │                                                                         │
    │ Q3. `Timestamp` uses the non-ISO format "DD/MM/YYYY HH:MM:SS".         │
    │     Day-first ordering is a silent correctness trap for US-locale tools.│
    │     → Parsed with dayfirst=True; output as ISO 8601 string.             │
    │     → On parse failure, the raw string is preserved (not zeroed).      │
    │       Silent data loss is worse than a slightly malformed timestamp.    │
    │                                                                         │
    │ Q4. `Flow Duration` is already in microseconds per CICFlowMeter spec.  │
    │     → Direct int cast; no unit conversion needed.                       │
    │                                                                         │
    │ Q5. No `Src Port` column in standard CIC-IDS2018 files.                │
    │     The dataset is flow-feature-centric and omits L4 source ports.     │
    │     → Defaults to 0; alternate spellings tried as a guard.              │
    │                                                                         │
    │ Q6. Throughput column uses CIC's famous typo "Flow Byts/s"             │
    │     (not "Bytes"). Both spellings are tried; first non-None wins.      │
    │                                                                         │
    │ Q7. Flows with very short duration produce ±inf bytes/s after          │
    │     CICFlowMeter's internal division. These are replaced with 0 by     │
    │     the bulk chunk-level sanitization in Stage 2 of _process_chunk.    │
    │     sanitize_float() provides an independent second defence layer.     │
    └─────────────────────────────────────────────────────────────────────────┘

    Args:
        row: Single CSV row as a Python dict. Column headers must already be
             stripped of whitespace (this is guaranteed by _process_chunk).
    Returns:
        Dict whose keys exactly match the fields of UnifiedSecurityLog.
    """
    # ── Q2: Protocol — integer IANA code → canonical string ──────────────────
    raw_proto = sanitize_int(row.get("Protocol", 0), default=0)
    protocol  = IDS2018_PROTO_MAP.get(raw_proto, "Unknown")

    # ── Q3: Timestamp — "DD/MM/YYYY HH:MM:SS" → ISO 8601 ────────────────────
    raw_ts = sanitize_str(row.get("Timestamp", ""), default="")
    if raw_ts:
        try:
            # dayfirst=True is non-negotiable: 02/03/2018 is 2 March, not 3 Feb.
            ts = pd.to_datetime(raw_ts, dayfirst=True).isoformat()
        except Exception:
            # Preserve the original string on failure. A downstream retry is
            # better than silently replacing a real timestamp with epoch zero.
            ts = raw_ts
    else:
        ts = "1970-01-01T00:00:00"  # Unix epoch sentinel for truly absent values.

    # ── Q4: Flow Duration — already in microseconds ───────────────────────────
    flow_dur = sanitize_int(row.get("Flow Duration", 0), default=0)

    # ── Q5: Ports — Src Port may be absent in some IDS2018 file versions ──────
    src_port = clamp_port(row.get("Src Port", row.get("Source Port", 0)))
    dst_port = clamp_port(row.get("Dst Port", row.get("Destination Port", 0)))

    # ── Q6: Throughput — tolerate both "Byts" (CIC typo) and "Bytes" ─────────
    bps = sanitize_float(
        row.get("Flow Byts/s",
        row.get("Flow Bytes/s",
        row.get("Flow Byts/S",       # Occasional capitalisation variant
        0.0)))
    )
    pps = sanitize_float(
        row.get("Flow Pkts/s",
        row.get("Flow Packets/s",
        row.get("Flow Pkts/S",
        0.0)))
    )

    # ── Label — exact classification string from the dataset ──────────────────
    label = sanitize_str(row.get("Label", ""), default="UNKNOWN")

    return {
        "source_dataset":     "IDS2018",
        "timestamp":          ts,
        "protocol":           protocol,
        "flow_duration":      flow_dur,
        "source_port":        src_port,
        "destination_port":   dst_port,
        "bytes_per_second":   bps,
        "packets_per_second": pps,
        "ground_truth_label": label,
    }


def parse_doh2020_row(row: dict) -> dict:
    """
    Translate one CIC-DoHBrw-2020 flow record into a UnifiedSecurityLog field dict.

    ┌─────────────────────────────────────────────────────────────────────────┐
    │ CIC-DoHBrw-2020 Quirk Register — all dataset-specific issues resolved  │
    ├─────────────────────────────────────────────────────────────────────────┤
    │ Q1. No Protocol column exists anywhere in the DoH2020 schema.          │
    │     DNS-over-HTTPS mandates TLS, which runs exclusively over TCP.      │
    │     → Protocol is hardcoded to "TCP". No lookup required.              │
    │                                                                         │
    │ Q2. DestinationPort should always be 443 (HTTPS/TLS).                  │
    │     Files can be malformed or the column missing; we enforce it.       │
    │     → If DestinationPort is 0 or absent, it is set to 443.             │
    │                                                                         │
    │ Q3. `Duration` is in SECONDS (float), NOT microseconds.                │
    │     CIC-IDS2018 uses microseconds; DoH2020 does not. This is the       │
    │     most dangerous inter-dataset discrepancy for downstream ML.        │
    │     → Multiplied by 1_000_000 before int() cast.                       │
    │                                                                         │
    │ Q4. Throughput is split into directional rate columns:                 │
    │       FlowSentRate / FlowReceivedRate     (bytes/sec)                  │
    │       PacketSentRate / PacketReceivedRate (packets/sec)                │
    │     → Summed to produce bidirectional totals matching our contract.    │
    │                                                                         │
    │ Q5. Fallback: if explicit rate columns are zero or absent, derive      │
    │     rates from raw byte/packet count columns divided by duration.      │
    │     This covers older DoH2020 file versions with a different schema.  │
    │                                                                         │
    │ Q6. Timestamp column name varies across DoH2020 file versions:        │
    │     "TimeStamp", "Timestamp", "timestamp". All three are tried.        │
    │                                                                         │
    │ Q7. Label column name varies: "Label", "label", "CLASS".               │
    └─────────────────────────────────────────────────────────────────────────┘

    Args:
        row: Single CSV row as a Python dict. Column headers must already be
             stripped of whitespace (guaranteed by _process_chunk).
    Returns:
        Dict whose keys exactly match the fields of UnifiedSecurityLog.
    """
    # ── Q1: Protocol — DoH mandates TLS/HTTPS, therefore always TCP ──────────
    protocol = "TCP"

    # ── Q6: Timestamp — column name varies across DoH2020 file versions ───────
    raw_ts = sanitize_str(
        row.get("TimeStamp",
        row.get("Timestamp",
        row.get("timestamp", ""))),
        default=""
    )
    if raw_ts:
        try:
            # pd.to_datetime handles the ISO-adjacent "YYYY-MM-DDTHH:MM:SS.ffffff"
            # format natively with no extra configuration required.
            ts = pd.to_datetime(raw_ts).isoformat()
        except Exception:
            ts = raw_ts
    else:
        ts = "1970-01-01T00:00:00"

    # ── Q3: Flow Duration — SECONDS (float) → MICROSECONDS (int) ─────────────
    raw_dur_s = sanitize_float(row.get("Duration", 0.0), default=0.0)
    flow_dur  = int(raw_dur_s * 1_000_000)

    # ── Q2: Ports — enforce destination port 443 for DoH traffic ─────────────
    src_port = clamp_port(row.get("SourcePort",      row.get("Source Port", 0)))
    dst_port = clamp_port(row.get("DestinationPort", row.get("Destination Port", 0)))
    if dst_port == 0:
        dst_port = 443  # DoH MUST target 443; zero means the column was missing.

    # ── Q4: Throughput — sum directional rates for bidirectional total ─────────
    sent_rate = sanitize_float(
        row.get("FlowSentRate",      row.get("flowSentRate",     0.0))
    )
    recv_rate = sanitize_float(
        row.get("FlowReceivedRate",  row.get("flowReceivedRate", 0.0))
    )
    bps = sent_rate + recv_rate

    pkt_sent  = sanitize_float(
        row.get("PacketSentRate",     row.get("packetSentRate",     0.0))
    )
    pkt_recv  = sanitize_float(
        row.get("PacketReceivedRate", row.get("packetReceivedRate", 0.0))
    )
    pps = pkt_sent + pkt_recv

    # ── Q5: Fallback — derive from raw totals when rate columns are absent ─────
    # Guards against older DoH2020 file schema variants that lack rate columns.
    if bps == 0.0 and raw_dur_s > 0.0:
        total_bytes = (
            sanitize_float(row.get("FlowBytesSent",     row.get("flowBytesSent",     0.0)))
            + sanitize_float(row.get("FlowBytesReceived", row.get("flowBytesReceived", 0.0)))
        )
        bps = total_bytes / raw_dur_s

    if pps == 0.0 and raw_dur_s > 0.0:
        total_pkts = (
            sanitize_float(row.get("PacketsSent",     row.get("packetsSent",     0.0)))
            + sanitize_float(row.get("PacketsReceived", row.get("packetsReceived", 0.0)))
        )
        pps = total_pkts / raw_dur_s

    # ── Q7: Label — known values: "Benign", "Malicious", "NonDoH", "DoH" ──────
    label = sanitize_str(
        row.get("Label", row.get("label", row.get("CLASS", ""))),
        default="UNKNOWN"
    )

    return {
        "source_dataset":     "DoH2020",
        "timestamp":          ts,
        "protocol":           protocol,
        "flow_duration":      flow_dur,
        "source_port":        src_port,
        "destination_port":   dst_port,
        "bytes_per_second":   bps,
        "packets_per_second": pps,
        "ground_truth_label": label,
    }


# ── Mapper Registry ───────────────────────────────────────────────────────────
# Maps DatasetType → translation function.
# Adding a new dataset requires: (1) write a new parse_*_row function, and
# (2) add one entry here. Zero changes to the processing engine are needed.
MAPPER_REGISTRY: dict[str, Callable[[dict], dict]] = {
    "IDS2018": parse_ids2018_row,
    "DoH2020": parse_doh2020_row,
}


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 4 — CORE STREAM PROCESSING ENGINE                                 ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _process_chunk(
    chunk: pd.DataFrame,
    dataset_type: DatasetType,
) -> tuple[list[UnifiedSecurityLog], int]:
    """
    Run one pandas DataFrame chunk through the four-stage ingestion pipeline.

    Stage 1 — Header normalisation
        Strip leading/trailing whitespace from every column name.
        Resolves CIC-IDS2018's notorious hidden-space headers like " Dst Port ".
        Applied once per chunk (O(cols)), not per row (O(rows × cols)).

    Stage 2 — Bulk numeric sanitisation
        Replace ±inf with NaN, then fillna(0) — on NUMERIC columns only.
        String columns are intentionally left untouched so that legitimate
        string values (labels, IPs) are never silently zeroed.
        The per-cell sanitize_* functions in the mapper provide a second,
        independent defence layer for individual cells that slip through.

    Stage 3 — Per-row translation
        Apply the dataset-specific mapper function (looked up from MAPPER_REGISTRY)
        to transform raw column names/values into the unified schema dictionary.

    Stage 4 — Pydantic validation
        Instantiate UnifiedSecurityLog from the mapped dict.
        Any validation or mapping failure is ISOLATED to the current row:
          • Error is logged to stderr with full type, message, and key context.
          • The row is silently dropped from output.
          • The loop continues with the next row — the pipeline never raises.

    Args:
        chunk:        Raw DataFrame chunk from pd.read_csv iterator.
        dataset_type: Identifies which mapper function to apply.

    Returns:
        (validated_logs, n_failed) — counts feed accurate stream-level telemetry.
    """
    # ── Stage 1: Normalise column headers ─────────────────────────────────────
    # This single line resolves CIC's infamous hidden-space column names.
    # Must run before the mapper functions attempt any column.get() lookups.
    chunk.columns = pd.Index([str(c).strip() for c in chunk.columns])

    # ── Stage 2: Bulk numeric sanitisation ────────────────────────────────────
    # Only target dtype-numeric columns to avoid corrupting string columns.
    numeric_cols = chunk.select_dtypes(include="number").columns.tolist()
    if numeric_cols:
        chunk[numeric_cols] = (
            chunk[numeric_cols]
            .replace([float("inf"), float("-inf")], float("nan"))
            .fillna(0)
        )

    mapper_fn                            = MAPPER_REGISTRY[dataset_type]
    validated: list[UnifiedSecurityLog]  = []
    n_failed                             = 0

    # ── Stages 3 + 4: Per-row translation and Pydantic validation ─────────────
    for idx, series in chunk.iterrows():
        raw: dict = series.to_dict()
        try:
            # Stage 3: dataset-specific field mapping
            mapped: dict = mapper_fn(raw)

            # Stage 4: Pydantic contract validation
            log_entry = UnifiedSecurityLog(**mapped)
            validated.append(log_entry)

        except Exception as exc:
            n_failed += 1
            # Surface the EXACT error type and message to stderr.
            # Dumping the first 10 keys provides debug context without
            # flooding the log with potentially sensitive full row data.
            log.warning(
                "Row REJECTED | dataset=%-8s | row_index=%s | "
                "error_type=%-30s | message=%s | first_10_columns=%s",
                dataset_type,
                idx,
                type(exc).__name__,
                str(exc),
                list(raw.keys())[:10],
            )

    return validated, n_failed


def stream_and_process(
    file_path:    Path,
    dataset_type: DatasetType,
    chunk_size:   int           = CHUNK_SIZE,
    row_limit:    Optional[int] = None,
) -> list[UnifiedSecurityLog]:
    """
    Stream a gigabyte-scale CSV file in memory-safe chunks through the pipeline.

    Memory Guarantee
    ─────────────────
    `pd.read_csv(chunksize=N)` returns a `TextFileReader` — a lazy iterator,
    not an in-memory object. Each chunk (at most `chunk_size` rows) is fetched,
    processed through the pipeline, and released to the garbage collector before
    the next chunk is loaded. Peak heap usage is bounded to:
        ≈ chunk_size × avg_row_bytes_in_memory
    regardless of the total file size. A 10 GB CSV with chunk_size=10_000 never
    requires more than ~50–100 MB of RAM for the active chunk.

    Fault Isolation
    ────────────────
    Row-level failures are absorbed inside _process_chunk (never propagated).
    File-level errors (not found, empty, encoding issues) are logged to stderr
    and an empty list is returned. The caller is responsible for deciding whether
    an empty result is a fatal error or an acceptable outcome.

    Args:
        file_path:    Path to the CSV dataset file on disk.
        dataset_type: "IDS2018" or "DoH2020" — selects the mapper function.
        chunk_size:   Rows per pandas chunk. See module-level CHUNK_SIZE notes.
        row_limit:    Maximum total rows to process (None = entire file).
                      Set to a small integer for smoke-testing without reading
                      multi-GB files end-to-end.

    Returns:
        List of all validated UnifiedSecurityLog objects from this file.
        Returns [] (does not raise) on any file-level error.
    """
    if not file_path.exists():
        log.error("Dataset file not found — skipping: %s", file_path)
        return []

    all_logs:       list[UnifiedSecurityLog] = []
    rows_consumed   = 0
    rows_validated  = 0
    rows_failed     = 0
    chunk_count     = 0

    # Log at WARNING so this header is visible at the default log level
    # without requiring the caller to lower to DEBUG.
    log.warning(
        "STREAM START | file=%-55s | dataset=%-8s | chunk_size=%d | row_limit=%s",
        file_path.name, dataset_type, chunk_size, row_limit or "unlimited",
    )

    try:
        # `low_memory=False` disables pandas' per-column dtype sniffing pass,
        # which re-reads the file and is both slow and unreliable on CIC CSVs
        # where a single column can contain mixed numeric and string sentinel values.
        reader = pd.read_csv(
            file_path,
            chunksize=chunk_size,
            low_memory=False,
            encoding="utf-8",
            on_bad_lines="warn",    # Log malformed rows; do NOT abort the stream.
        )

        for chunk in reader:
            # ── Row-limit guard: trim the current chunk if needed ──────────────
            # We check before incrementing rows_consumed so the slice is based
            # on how many rows we have processed so far.
            if row_limit is not None:
                remaining = row_limit - rows_consumed
                if remaining <= 0:
                    break
                if len(chunk) > remaining:
                    # .copy() prevents a SettingWithCopyWarning when _process_chunk
                    # modifies the trimmed slice in-place (column dtype coercions).
                    chunk = chunk.iloc[:remaining].copy()

            chunk_len    = len(chunk)
            chunk_count += 1

            validated, n_failed = _process_chunk(chunk, dataset_type)
            all_logs.extend(validated)

            rows_consumed  += chunk_len
            rows_validated += len(validated)
            rows_failed    += n_failed

            log.debug(
                "Chunk %4d | rows=%5d | ok=%5d | fail=%3d | cumulative_ok=%d",
                chunk_count, chunk_len, len(validated), n_failed, rows_validated,
            )

            # Secondary guard: exit after the chunk that crosses the row_limit.
            if row_limit is not None and rows_consumed >= row_limit:
                break

    except pd.errors.EmptyDataError:
        log.error("CSV file is empty or has no parseable columns: %s", file_path)
    except UnicodeDecodeError as exc:
        log.error(
            "Encoding error reading %s — try encoding='latin-1' if the file "
            "uses Windows-1252: %s", file_path, exc
        )
    except Exception as exc:
        log.error(
            "Unexpected failure in stream_and_process | file=%s | %s: %s",
            file_path, type(exc).__name__, exc, exc_info=True,
        )

    log.warning(
        "STREAM END   | file=%-55s | chunks=%d | consumed=%d | "
        "validated=%d | failed=%d",
        file_path.name, chunk_count, rows_consumed, rows_validated, rows_failed,
    )

    return all_logs


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 5 — SYNTHETIC TEST DATA GENERATORS                                ║
# ║  Enables immediate local verification without real dataset files.           ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _write_ids2018_sample(path: Path, n: int = 10) -> None:
    """
    Write a minimal CIC-IDS2018-compatible CSV at *path*.

    Deliberately reproduces real-world CIC quirks for end-to-end pipeline testing:
      • Column headers have LEADING SPACES — tests Stage-1 header stripping.
      • Row index 2 contains "Infinity" in the bytes/s column — tests inf handling.
      • Row index 4 has an empty Label — tests the sanitize_str fallback.
      • Mixed protocol integers including unmapped codes — tests IDS2018_PROTO_MAP.
    """
    random.seed(42)
    labels = ["BENIGN", "DDoS", "DoS Hulk", "PortScan", "Bot", "Infilteration"]
    protos = [6, 17, 0, 58, 41]   # TCP, UDP, Unknown (×3)

    # Deliberate leading spaces on headers — this is the canonical CIC format
    fieldnames = [
        " Dst Port", " Protocol", " Timestamp", " Flow Duration",
        " Flow Byts/s", " Flow Pkts/s", " Label",
    ]

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for i in range(n):
            # Row 2: inject "Infinity" to validate Stage-2 bulk sanitization
            bps_val = "Infinity" if i == 2 else round(random.uniform(100, 5_000_000), 4)
            # Row 4: empty label to test sanitize_str default fallback
            lbl_val = "" if i == 4 else random.choice(labels)
            writer.writerow({
                " Dst Port":      random.randint(1, 65535),
                " Protocol":      random.choice(protos),
                " Timestamp":     (
                    f"{random.randint(14, 22):02d}/02/2018 "
                    f"{random.randint(0, 23):02d}:"
                    f"{random.randint(0, 59):02d}:"
                    f"{random.randint(0, 59):02d}"
                ),
                " Flow Duration": random.randint(500, 50_000_000),   # microseconds
                " Flow Byts/s":   bps_val,
                " Flow Pkts/s":   round(random.uniform(1, 50_000), 4),
                " Label":         lbl_val,
            })

    log.warning("IDS2018 synthetic sample written: %s (%d rows)", path, n)


def _write_doh2020_sample(path: Path, n: int = 10) -> None:
    """
    Write a minimal CIC-DoHBrw-2020-compatible CSV at *path*.

    Deliberately reproduces real-world DoH2020 quirks:
      • DestinationPort = 0 on row 3 — tests the dst_port=443 enforcement.
      • Duration in fractional seconds — tests μs conversion correctness.
      • Real-looking Cloudflare/Google DoH resolver IPs as destinations.
    """
    random.seed(99)
    labels    = ["Benign", "Malicious", "NonDoH"]
    resolvers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]
    base_ts   = datetime(2020, 6, 15, 8, 0, 0)

    fieldnames = [
        "TimeStamp", "SourceIP", "DestinationIP",
        "SourcePort", "DestinationPort", "Duration",
        "FlowBytesSent", "FlowSentRate",
        "FlowBytesReceived", "FlowReceivedRate",
        "PacketsSent", "PacketsReceived",
        "PacketSentRate", "PacketReceivedRate",
        "Label",
    ]

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for i in range(n):
            dur    = round(random.uniform(0.001, 4.999), 6)   # seconds
            b_sent = random.randint(200,  60_000)
            b_recv = random.randint(500, 200_000)
            p_sent = random.randint(2, 120)
            p_recv = random.randint(3, 400)
            writer.writerow({
                "TimeStamp":          (base_ts + timedelta(seconds=i * 0.75)).isoformat(),
                "SourceIP":           f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "DestinationIP":      random.choice(resolvers),
                "SourcePort":         random.randint(1024, 65535),
                # Row 3: 0 destination port to trigger the enforcement guard
                "DestinationPort":    0 if i == 3 else 443,
                "Duration":           dur,
                "FlowBytesSent":      b_sent,
                "FlowSentRate":       round(b_sent / dur, 4),
                "FlowBytesReceived":  b_recv,
                "FlowReceivedRate":   round(b_recv / dur, 4),
                "PacketsSent":        p_sent,
                "PacketsReceived":    p_recv,
                "PacketSentRate":     round(p_sent / dur, 4),
                "PacketReceivedRate": round(p_recv / dur, 4),
                "Label":              random.choice(labels),
            })

    log.warning("DoH2020 synthetic sample written: %s (%d rows)", path, n)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 6 — LOCAL VERIFICATION MAIN LOOP                                  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

if __name__ == "__main__":
    import textwrap

    # ─────────────────────────────────────────────────────────────────────────
    # ▶  CONFIGURE YOUR DATASET PATHS HERE
    # ─────────────────────────────────────────────────────────────────────────
    #
    # Point these variables at your actual CIC dataset CSV files:
    #
    #   IDS2018 download:
    #     https://www.unb.ca/cic/datasets/ids-2018.html
    #     Example file: Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
    #
    #   DoH2020 download:
    #     https://www.unb.ca/cic/datasets/dohbrw-2020.html
    #     Example file: l1-benign-doh.csv
    #
    # If either path does not exist, the script AUTO-GENERATES a synthetic
    # sample CSV that faithfully reproduces the dataset's column structure and
    # known quirks — so you can verify the full pipeline immediately.
    #
    IDS2018_CSV = Path("/Volumes/Expansion/CyberML_Dataset/CSVs/Total_CSVs")
    DOH2020_CSV = Path("/Volumes/Expansion/CyberML_Dataset/archive")
    # ─────────────────────────────────────────────────────────────────────────

    VERIFY_N = 5   # Exact number of rows to read and validate per dataset.

    # ── Terminal colour helpers ───────────────────────────────────────────────
    # Degrade gracefully on terminals that do not support ANSI escape codes.
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    RED    = "\033[91m"
    SEP    = "═" * 72
    SUBSEP = "─" * 72

    # ── Banner ────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{BLUE}{SEP}{RESET}")
    print(
        f"{BOLD}{BLUE}  UNIFIED SECURITY LOG INGESTION PIPELINE  "
        f"—  PHASE 1 VERIFICATION{RESET}"
    )
    print(f"{BOLD}{BLUE}{SEP}{RESET}")
    print(textwrap.dedent(f"""
    {BOLD}Runtime Configuration{RESET}
      IDS2018 path   : {IDS2018_CSV}
      DoH2020 path   : {DOH2020_CSV}
      Rows/dataset   : {VERIFY_N}  (one micro-chunk per dataset)
      Chunk size     : {VERIFY_N}  (verification mode — chunk == row limit)
      pandas version : {pd.__version__}
      pydantic ver.  : {pydantic.VERSION}
    """))

    # ── Auto-generate synthetic samples when real files are not present ───────
    IDS2018_CSV.parent.mkdir(parents=True, exist_ok=True)
    DOH2020_CSV.parent.mkdir(parents=True, exist_ok=True)

    if not IDS2018_CSV.exists():
        print(
            f"  {YELLOW}[AUTO-GEN]{RESET} IDS2018 file not found — "
            f"generating synthetic sample with embedded quirks…"
        )
        # Generate slightly more rows than VERIFY_N so the chunk-trim path is exercised.
        _write_ids2018_sample(IDS2018_CSV, n=VERIFY_N + 5)

    if not DOH2020_CSV.exists():
        print(
            f"  {YELLOW}[AUTO-GEN]{RESET} DoH2020 file not found — "
            f"generating synthetic sample with embedded quirks…"
        )
        _write_doh2020_sample(DOH2020_CSV, n=VERIFY_N + 5)

    # ── Process each dataset and print validated records ──────────────────────
    results: dict[str, list[UnifiedSecurityLog]] = {}

    for ds_type, csv_path in [("IDS2018", IDS2018_CSV), ("DoH2020", DOH2020_CSV)]:
        print(f"\n{SUBSEP}")
        print(
            f"{BOLD}{CYAN}  [{ds_type}]{RESET}  "
            f"Streaming {VERIFY_N} rows from: {BOLD}{csv_path}{RESET}"
        )
        print(f"{SUBSEP}")

        logs = stream_and_process(
            file_path    = csv_path,
            dataset_type = ds_type,          # type: ignore[arg-type]
            chunk_size   = VERIFY_N,         # Micro-chunk exactly matches our limit
            row_limit    = VERIFY_N,
        )
        results[ds_type] = logs

        if not logs:
            print(
                f"\n  {RED}⚠  No valid records produced for [{ds_type}].{RESET}\n"
                f"  Check:\n"
                f"    • The CSV file exists at the configured path.\n"
                f"    • Column names match the expected CIC dataset format.\n"
                f"    • Row-level ValidationErrors are printed to stderr above.\n"
            )
            continue

        # Print each validated record as pretty-printed JSON via Pydantic's
        # built-in model_dump_json() — guarantees valid JSON output every time.
        for i, entry in enumerate(logs, start=1):
            label_tag = f"[{entry.ground_truth_label}]"
            print(
                f"\n  {BOLD}Record #{i}{RESET}  "
                f"{GREEN}{label_tag}{RESET}  "
                f"protocol={CYAN}{entry.protocol}{RESET}"
            )
            json_str = entry.model_dump_json(indent=2)
            # Indent the JSON block for clean console alignment with the heading above.
            indented = "\n".join(f"    {line}" for line in json_str.splitlines())
            print(indented)

    # ── Verification Summary ──────────────────────────────────────────────────
    print(f"\n{BOLD}{BLUE}{SEP}{RESET}")
    print(f"{BOLD}{BLUE}  VERIFICATION SUMMARY{RESET}")
    print(f"{BOLD}{BLUE}{SEP}{RESET}")

    all_passed = True
    for ds_type, logs in results.items():
        ok   = len(logs)
        icon = f"{GREEN}✓" if ok == VERIFY_N else (f"{YELLOW}~" if ok > 0 else f"{RED}✗")
        note = ""
        if ok < VERIFY_N:
            note = f"  ← {VERIFY_N - ok} row(s) dropped (see stderr)"
            all_passed = False
        print(f"  {icon}  {ds_type:<12}{RESET}  {ok}/{VERIFY_N} records validated{note}")

    final_msg = (
        f"{GREEN}Pipeline OK — all {VERIFY_N * 2} records passed validation.{RESET}"
        if all_passed
        else f"{YELLOW}Some records failed — inspect stderr output above for details.{RESET}"
    )
    print(f"\n  {BOLD}{final_msg}{RESET}")
    print(f"{BOLD}{BLUE}{SEP}{RESET}\n")
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PHASE 1: DATA CONTRACTS & INGESTION ENGINE                                 ║
║  Autonomous Multi-Agent Threat Intelligence System                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Processes CIC-IDS2018 and CIC-DoHBrw-2020 cybersecurity datasets from      ║
║  directories of partitioned CSVs, cleanses messy/corrupt records, and       ║
║  normalises each row into a unified Pydantic v2 JSON data contract.          ║
║                                                                              ║
║  Architecture:                                                               ║
║    Section 0 ── Logging Configuration                                        ║
║    Section 1 ── Pipeline Constants & Column Alias Maps                       ║
║    Section 2 ── Unified Data Contract  (Pydantic v2 BaseModel)               ║
║    Section 3 ── Row-level Sanitisation Helpers                               ║
║    Section 4 ── Translation Layer  (dataset-specific mapper functions)       ║
║    Section 5 ── Memory-Safe CSV Chunk Streamer  (generator)                  ║
║    Section 6 ── Dataset-level Ingestion Pipelines  (directory traversal)     ║
║    Section 7 ── Test Execution Main Loop                                     ║
║                                                                              ║
║  Dependencies:  pip install pandas pydantic                                  ║
║  Tested with:   pandas >= 1.4, pydantic >= 2.0                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

# ── Standard Library ──────────────────────────────────────────────────────────
import math
import sys
import logging
from pathlib import Path
from typing import Generator, Literal, Optional

# ── Third-Party ───────────────────────────────────────────────────────────────
import pandas as pd
from pydantic import BaseModel, Field, field_validator, ValidationError


# =============================================================================
# SECTION 0 — Logging Configuration
# =============================================================================
# Two independent log streams:
#   • stdout  → INFO-level pipeline progress (file traversal, chunk counts)
#   • stderr  → WARNING-level per-row validation failures (corrupted records)
#
# This lets operators pipe stdout to a log file and stderr to an alert sink
# (e.g. PagerDuty webhook) without mixing concerns.
# =============================================================================

_LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format=_LOG_FORMAT,
    datefmt=_DATE_FORMAT,
)

# Dedicated validation-error logger that writes exclusively to stderr
_val_logger = logging.getLogger("validation.stderr")
_val_logger.propagate = False  # ← never bubble up to the root stdout handler

_stderr_handler = logging.StreamHandler(sys.stderr)
_stderr_handler.setLevel(logging.WARNING)
_stderr_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
_val_logger.addHandler(_stderr_handler)
_val_logger.setLevel(logging.WARNING)

logger = logging.getLogger("ingestion_engine")


# =============================================================================
# SECTION 1 — Pipeline Constants & Column Alias Maps
# =============================================================================
# CHUNK_SIZE   Controls memory footprint: a 10 000-row chunk of 80-column
#              float data occupies roughly 6–8 MB before sanitisation.
#              Reduce on constrained nodes; increase for throughput on RAM-rich
#              workers.
#
# US_PER_SECOND  Unit-conversion multiplier: DoH2020 stores duration in seconds
#                (float); IDS2018 stores it in microseconds (int).  We always
#                emit microseconds in the unified schema.
#
# Column alias maps provide resilience against minor header variations across
# dataset partitions (e.g. "Flow Byts/s" vs "Flow Bytes/s").  Each key is an
# internal logical field name; values are ordered lists tried left-to-right.
# =============================================================================

CHUNK_SIZE:    int = 10_000       # Rows per Pandas read_csv chunk
US_PER_SECOND: int = 1_000_000   # µs/s – DoH duration conversion factor

# ── IDS2018: numeric protocol code → canonical label ─────────────────────────
# IANA-assigned transport protocol numbers that appear in CIC-IDS2018.
# All other values map to "Unknown".
_IDS_PROTO_MAP: dict[int, str] = {
    6:  "TCP",   # IANA RFC 793
    17: "UDP",   # IANA RFC 768
}

# ── IDS2018: column alias resolution map ─────────────────────────────────────
# CICFlowMeter output varies slightly across dataset release versions.
# Headers are searched in priority order (index 0 first).
_IDS_COLS: dict[str, list[str]] = {
    "timestamp":        ["Timestamp",        "timestamp",      "Time"],
    "src_port":         ["Src Port",         "Source Port",    "SrcPort",   "src_port"],
    "dst_port":         ["Dst Port",         "Destination Port","DstPort",  "dst_port"],
    "flow_duration":    ["Flow Duration",    "FlowDuration",   "Duration_us"],
    "bytes_per_sec":    ["Flow Byts/s",      "Flow Bytes/s",   "FlowBytes/s",
                         "Bwd Byts/s",       "Fwd Byts/s"],
    "packets_per_sec":  ["Flow Pkts/s",      "Flow Packets/s", "FlowPackets/s",
                         "Fwd Pkts/s",       "Bwd Pkts/s"],
    "protocol":         ["Protocol",         "protocol"],
    "label":            ["Label",            "label",          "Class"],
}

# ── DoH2020: column alias resolution map ─────────────────────────────────────
# CIC-DoHBrw-2020 uses a behavioural-feature schema quite different from
# CICFlowMeter; column name casing also differs across published splits.
_DOH_COLS: dict[str, list[str]] = {
    "timestamp":        ["TimeStamp",        "Timestamp",      "timestamp"],
    "src_port":         ["SourcePort",       "Src Port",       "SrcPort",   "source_port"],
    "dst_port":         ["DestinationPort",  "Dst Port",       "DstPort",   "destination_port"],
    "duration":         ["Duration",         "duration",       "FlowDuration_s"],
    "pkt_count":        ["PacketCount",      "packetcount",    "NPackets"],
    "pkt_len_mean":     ["PacketLengthMean", "MeanPacketLength","pktLenMean"],
    "flow_bytes_sent":  ["FlowBytesSent",    "BytesSent",      "TotalBytes"],
    "label":            ["Label",            "label",          "Class",     "category"],
}

# Valid canonical protocol strings accepted by the Pydantic Literal field
_VALID_PROTOCOLS = frozenset({"TCP", "UDP", "Unknown"})


# =============================================================================
# SECTION 2 — Unified Data Contract  (Pydantic v2)
# =============================================================================
# UnifiedSecurityLog is the single source of truth for every downstream
# consumer (vector store, SIEM forwarder, ML feature extractor, etc.).
# It hides all structural and unit differences between IDS2018 and DoH2020
# behind a stable, validated interface.
#
# Design decisions:
#   • Literal["IDS2018", "DoH2020"]  → compile-time provenance tracking
#   • flow_duration as int (µs)       → lossless integer arithmetic for
#                                       downstream time-window aggregation
#   • ge/le constraints on ports      → enforced by Pydantic, no manual checks
#   • ge=0 on floats                  → negative bps/pps is physically impossible
#   • All "before" validators run on  → raw input before type coercion, so they
#                                       handle str/float/None/nan/inf safely
# =============================================================================

class UnifiedSecurityLog(BaseModel):
    """
    Canonical network-flow security log record.

    Abstracts structural differences between CIC-IDS2018 (CICFlowMeter-based,
    flow-level features, µs durations) and CIC-DoHBrw-2020 (DNS-over-HTTPS
    behavioural features, second-level durations).

    Every field is defensively coerced: NaN/inf/None → zero; empty strings →
    "UNKNOWN"; out-of-range ports → clamped.  A record that reaches this model
    will ALWAYS serialise to valid JSON.
    """

    source_dataset:     Literal["IDS2018", "DoH2020"] = Field(
        ...,
        description="Origin dataset tag; never inferred — always set by the mapper."
    )
    timestamp:          str = Field(
        ...,
        description="Original timestamp string from the dataset; format varies by source."
    )
    protocol:           Literal["TCP", "UDP", "Unknown"] = Field(
        ...,
        description="Layer-4 transport protocol.  IDS2018 maps numeric codes; "
                    "DoH2020 defaults to TCP (HTTPS transport)."
    )
    flow_duration:      int = Field(
        ...,
        ge=0,
        description="Network flow duration in microseconds.  "
                    "IDS2018: pass-through.  DoH2020: converted from seconds."
    )
    source_port:        int = Field(..., ge=0, le=65535)
    destination_port:   int = Field(..., ge=0, le=65535)
    bytes_per_second:   float = Field(
        ...,
        ge=0.0,
        description="Throughput in bytes/second.  "
                    "IDS2018: Flow Byts/s.  DoH2020: derived from pkt_len_mean × pps."
    )
    packets_per_second: float = Field(
        ...,
        ge=0.0,
        description="Throughput in packets/second.  "
                    "IDS2018: Flow Pkts/s.  DoH2020: PacketCount ÷ Duration."
    )
    ground_truth_label: str = Field(
        ...,
        description="Original dataset classification label (e.g. 'BENIGN', 'DoS', 'DoH')."
    )

    # ── Field validators (mode='before' → run on raw input before coercion) ──

    @field_validator("source_port", "destination_port", mode="before")
    @classmethod
    def _coerce_port(cls, v: object) -> int:
        """
        Coerce any port-like value to a valid integer in [0, 65535].
        NaN / inf / None → 0.  Values above 65535 are clamped (not rejected),
        because some CIC dataset rows carry mis-formatted port strings.
        """
        try:
            f = float(v)                          # type: ignore[arg-type]
            return min(65535, max(0, int(f))) if math.isfinite(f) else 0
        except (TypeError, ValueError):
            return 0

    @field_validator("flow_duration", mode="before")
    @classmethod
    def _coerce_duration(cls, v: object) -> int:
        """Coerce flow duration to a non-negative integer (microseconds)."""
        try:
            f = float(v)                          # type: ignore[arg-type]
            return max(0, int(f)) if math.isfinite(f) else 0
        except (TypeError, ValueError):
            return 0

    @field_validator("bytes_per_second", "packets_per_second", mode="before")
    @classmethod
    def _coerce_rate(cls, v: object) -> float:
        """
        Coerce throughput rate to a non-negative finite float.
        The CIC-IDS2018 dataset is notorious for inf values in Flow Byts/s
        (caused by zero-duration flows); these are silently normalised to 0.0.
        """
        try:
            f = float(v)                          # type: ignore[arg-type]
            return max(0.0, f) if math.isfinite(f) else 0.0
        except (TypeError, ValueError):
            return 0.0

    @field_validator("timestamp", "ground_truth_label", mode="before")
    @classmethod
    def _coerce_str(cls, v: object) -> str:
        """Strip and coerce any string-like value; replace nullish values with 'UNKNOWN'."""
        if v is None or (isinstance(v, float) and not math.isfinite(v)):
            return "UNKNOWN"
        cleaned = str(v).strip()
        return cleaned if cleaned else "UNKNOWN"

    @field_validator("protocol", mode="before")
    @classmethod
    def _normalise_protocol(cls, v: object) -> str:
        """
        Accept 'TCP', 'UDP', or 'Unknown' (case-insensitive); reject everything else
        by falling back to 'Unknown'.  Numeric codes must be resolved BEFORE this
        validator runs (done inside the mapper functions, not here).
        """
        if isinstance(v, str):
            upper = v.strip().upper()
            if upper in _VALID_PROTOCOLS:
                return upper
        return "Unknown"


# ── Required when `from __future__ import annotations` is active ──────────────
# PEP 563 defers all annotation evaluation to strings; Pydantic v2 must be
# explicitly told to re-resolve them against the current module namespace.
UnifiedSecurityLog.model_rebuild()


# =============================================================================
# SECTION 3 — Row-level Sanitisation Helpers
# =============================================================================
# These small helpers are called by both mapper functions.  Keeping them at
# module level (rather than inside the mappers) makes unit-testing trivial and
# avoids repeated closure allocation inside hot loops.
# =============================================================================

def _pick(row: dict, aliases: list[str], default=None):
    """
    Return the value of the first matching alias key found in *row*.
    Treats the value as missing if it is None; does NOT filter on 0 or "".

    Args:
        row:      Sanitised row dictionary.
        aliases:  Ordered list of candidate column names to probe.
        default:  Returned when no alias resolves to a non-None value.
    """
    for alias in aliases:
        if alias in row and row[alias] is not None:
            return row[alias]
    return default


def _safe_float(value: object, default: float = 0.0) -> float:
    """Parse *value* as a finite float; return *default* on failure."""
    try:
        f = float(value)                          # type: ignore[arg-type]
        return f if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def _safe_int(value: object, default: int = 0) -> int:
    """Parse *value* as an integer; return *default* on NaN/inf/parse failure."""
    try:
        f = float(value)                          # type: ignore[arg-type]
        return int(f) if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def _safe_str(value: object, default: str = "UNKNOWN") -> str:
    """Strip *value* to a non-empty string; return *default* for nullish input."""
    if value is None:
        return default
    s = str(value).strip()
    return s if s else default


def _sanitize_row_dict(row: dict) -> dict:
    """
    Global pre-sanitisation pass over an entire row dictionary.

    Replaces every non-finite float (NaN, +inf, -inf) and Python None
    with integer 0 so that downstream JSON serialisation never encounters
    values that are illegal in the JSON spec.

    This acts as a broad safety net *before* the dataset-specific mappers
    run, catching any column the mappers do not explicitly handle.

    Args:
        row: Raw dict from pd.Series.to_dict() — may contain numpy scalar types.

    Returns:
        New dict with the same keys; non-finite / None values replaced with 0.
    """
    clean: dict = {}
    for key, val in row.items():
        if val is None:
            clean[key] = 0
        elif isinstance(val, float) and not math.isfinite(val):
            clean[key] = 0
        else:
            clean[key] = val
    return clean


# =============================================================================
# SECTION 4 — Translation Layer  (Dataset-Specific Mapper Functions)
# =============================================================================
# Each mapper accepts a *sanitised* row dict and returns a plain dict of kwargs
# ready for UnifiedSecurityLog(**kwargs).
#
# Mappers are the ONLY place where dataset-specific column names, unit
# conversions, and protocol mappings live.  The Pydantic model is kept
# dataset-agnostic; new data sources only require a new mapper function.
# =============================================================================

def parse_ids2018_row(row: dict) -> dict:
    """
    Translate one sanitised CIC-IDS2018 row into a UnifiedSecurityLog kwarg dict.

    CIC-IDS2018 is generated by CICFlowMeter from the Canadian Institute for
    Cybersecurity's PCAP captures.  Key schema characteristics:

        Column          Type    Notes
        ─────────────── ─────── ─────────────────────────────────────────────
        Timestamp       str     "DD/MM/YYYY HH:MM:SS" (locale-dependent)
        Protocol        int     6 → TCP, 17 → UDP, others → "Unknown"
        Flow Duration   int     Already in microseconds — no conversion needed
        Src Port        int     TCP/UDP source port; may be missing in some splits
        Dst Port        int     TCP/UDP destination port
        Flow Byts/s     float   Can be +inf when Flow Duration == 0; we clamp
        Flow Pkts/s     float   Same inf risk as bytes/s
        Label           str     "BENIGN", "DoS Hulk", "PortScan", etc.

    Args:
        row: Pre-sanitised dict (all NaN/None/inf already replaced with 0).

    Returns:
        Dict of keyword arguments for UnifiedSecurityLog(**...).
    """
    # ── Protocol: numeric IANA code → canonical string ────────────────────────
    # Non-standard / unrecognised codes → "Unknown" (not a hard failure).
    raw_proto_int = _safe_int(_pick(row, _IDS_COLS["protocol"], default=0))
    protocol_str  = _IDS_PROTO_MAP.get(raw_proto_int, "Unknown")

    return {
        "source_dataset":     "IDS2018",
        "timestamp":          _safe_str(_pick(row, _IDS_COLS["timestamp"])),
        "protocol":           protocol_str,
        # Flow Duration is already µs in IDS2018 → pass through as int
        "flow_duration":      _safe_int(_pick(row, _IDS_COLS["flow_duration"])),
        "source_port":        _safe_int(_pick(row, _IDS_COLS["src_port"])),
        "destination_port":   _safe_int(_pick(row, _IDS_COLS["dst_port"])),
        # Flow Byts/s and Flow Pkts/s can be ±inf for zero-duration flows;
        # the Pydantic _coerce_rate validator will clamp them to 0.0.
        "bytes_per_second":   _safe_float(_pick(row, _IDS_COLS["bytes_per_sec"])),
        "packets_per_second": _safe_float(_pick(row, _IDS_COLS["packets_per_sec"])),
        "ground_truth_label": _safe_str(_pick(row, _IDS_COLS["label"])),
    }


def parse_doh2020_row(row: dict) -> dict:
    """
    Translate one sanitised CIC-DoHBrw-2020 row into a UnifiedSecurityLog kwarg dict.

    CIC-DoHBrw-2020 captures DNS-over-HTTPS flows from multiple browsers and
    DNS resolvers.  Key schema characteristics:

        Column              Type    Notes
        ─────────────────── ─────── ─────────────────────────────────────────
        TimeStamp           str     ISO 8601 / epoch depending on split version
        SourcePort          int     Ephemeral client port
        DestinationPort     int     Almost always 443; defaults to 443 when 0
        Duration            float   Seconds (NOT microseconds) → must convert
        PacketCount         int     Total packets in the flow
        PacketLengthMean    float   Mean payload size in bytes
        FlowBytesSent       int     Total bytes (some splits only)
        Label               str     "DoH", "NonDoH", "Malicious-*" etc.

    Transformations applied:
        1. duration (s)   →  flow_duration (µs):  int(duration × 1_000_000)
        2. DestinationPort == 0  →  443  (DoH canonical HTTPS port)
        3. Protocol               →  "TCP" by default (DoH runs over HTTPS/TCP);
                                     overridden if a numeric Protocol column exists
        4. bytes_per_second       →  FlowBytesSent / duration  OR
                                     PacketLengthMean × packets_per_second
        5. packets_per_second     →  PacketCount / duration (s)

    Args:
        row: Pre-sanitised dict (all NaN/None/inf already replaced with 0).

    Returns:
        Dict of keyword arguments for UnifiedSecurityLog(**...).
    """
    # ── Duration: seconds (float) → microseconds (int) ───────────────────────
    raw_duration_s = _safe_float(_pick(row, _DOH_COLS["duration"], default=0.0))
    flow_duration_us = int(raw_duration_s * US_PER_SECOND)

    # ── Destination port: default to 443 (HTTPS) when absent or zero ─────────
    raw_dst_port    = _safe_int(_pick(row, _DOH_COLS["dst_port"], default=0))
    destination_port = raw_dst_port if raw_dst_port > 0 else 443

    # ── packets_per_second: PacketCount ÷ Duration (guard against div/zero) ──
    pkt_count        = _safe_float(_pick(row, _DOH_COLS["pkt_count"], default=0.0))
    packets_per_sec  = (pkt_count / raw_duration_s) if raw_duration_s > 0.0 else 0.0

    # ── bytes_per_second: prefer explicit field; fall back to derived value ───
    # Priority:
    #   1. FlowBytesSent / Duration          (most accurate)
    #   2. PacketLengthMean × packets/s      (derived approximation)
    #   3. 0.0                               (last-resort default)
    flow_bytes_sent  = _safe_float(_pick(row, _DOH_COLS["flow_bytes_sent"], default=None))
    pkt_len_mean     = _safe_float(_pick(row, _DOH_COLS["pkt_len_mean"], default=0.0))

    if flow_bytes_sent is not None and raw_duration_s > 0.0:
        bytes_per_sec = flow_bytes_sent / raw_duration_s
    else:
        bytes_per_sec = pkt_len_mean * packets_per_sec

    # ── Protocol: DoH runs over HTTPS (TCP/443) by definition ────────────────
    # If the dataset happens to include a numeric Protocol column (some splits
    # do), resolve it through the IANA map; otherwise default to TCP.
    raw_proto_col = _pick(row, ["Protocol", "protocol"], default=None)
    if raw_proto_col is not None:
        proto_str = _IDS_PROTO_MAP.get(_safe_int(raw_proto_col), "TCP")
    else:
        proto_str = "TCP"

    return {
        "source_dataset":     "DoH2020",
        "timestamp":          _safe_str(_pick(row, _DOH_COLS["timestamp"])),
        "protocol":           proto_str,
        "flow_duration":      flow_duration_us,
        "source_port":        _safe_int(_pick(row, _DOH_COLS["src_port"])),
        "destination_port":   destination_port,
        "bytes_per_second":   bytes_per_sec,
        "packets_per_second": packets_per_sec,
        "ground_truth_label": _safe_str(_pick(row, _DOH_COLS["label"])),
    }


# =============================================================================
# SECTION 5 — Memory-Safe CSV Chunk Streamer
# =============================================================================
# A generator that wraps pd.read_csv(chunksize=N) to provide:
#   • Guaranteed file closure (context manager)
#   • Immediate header whitespace stripping on every chunk
#   • Optional per-file row ceiling (development / test mode)
#   • Graceful handling of empty files, missing files, encoding errors
#
# Memory guarantee: at any point in time only ONE chunk of CHUNK_SIZE rows
# is alive in the interpreter heap; all other chunks have been GC'd.
# =============================================================================

def stream_csv_chunks(
    csv_path: Path,
    chunk_size: int = CHUNK_SIZE,
    row_limit: Optional[int] = None,
) -> Generator[pd.DataFrame, None, None]:
    """
    Memory-safe generator: stream a single CSV file in fixed-size chunks.

    Opens the file, strips column-header whitespace, applies an optional row
    ceiling, and automatically closes the file when the generator is exhausted
    or garbage-collected.

    Args:
        csv_path:   Path object pointing to the target CSV file.
        chunk_size: Number of rows per Pandas TextFileReader chunk.
                    Tune this based on the node's RAM budget.
                    Rule of thumb: 10 000 rows × 80 float cols ≈ 6–8 MB.
        row_limit:  If set, stop yielding after this many total rows.
                    Used in test/dev mode to avoid reading entire files.

    Yields:
        pd.DataFrame — one chunk at a time, column headers already stripped.

    Note:
        ``pd.read_csv`` with ``chunksize`` returns a ``TextFileReader`` which
        implements the context manager protocol (pandas >= 1.2).  Using it
        inside a ``with`` block guarantees the underlying file descriptor is
        closed even if an exception is raised mid-stream.
    """
    rows_yielded: int = 0

    try:
        with pd.read_csv(
            csv_path,
            chunksize=chunk_size,
            low_memory=False,           # Prevents mixed-type column inference
            on_bad_lines="warn",        # Emit a warning; skip malformed rows
            encoding="utf-8",
            encoding_errors="replace",  # Replace un-decodable bytes with U+FFFD
        ) as reader:

            for chunk in reader:

                # ── MANDATORY: strip whitespace from every column header ──────
                # CICFlowMeter and other tools frequently emit headers with
                # leading spaces (e.g. " Src Port") that break column lookups.
                chunk.columns = chunk.columns.str.strip()

                # ── Enforce optional per-file row ceiling ────────────────────
                if row_limit is not None:
                    remaining = row_limit - rows_yielded
                    if remaining <= 0:
                        logger.debug(
                            "Row limit of %d reached for %s — stopping early.",
                            row_limit, csv_path.name,
                        )
                        return
                    # Slice and copy to avoid SettingWithCopyWarning downstream
                    chunk = chunk.iloc[:remaining].copy()

                rows_yielded += len(chunk)
                yield chunk

                if row_limit is not None and rows_yielded >= row_limit:
                    return

    except FileNotFoundError:
        logger.error("CSV not found           : %s", csv_path)
    except pd.errors.EmptyDataError:
        logger.warning("Empty CSV — skipping    : %s", csv_path)
    except UnicodeDecodeError as exc:
        logger.error("Encoding error in %s    : %s", csv_path, exc)
    except PermissionError:
        logger.error("Permission denied       : %s", csv_path)
    except Exception as exc:  # noqa: BLE001 — log and continue; don't crash pipeline
        logger.error(
            "Unexpected error reading %s : %s", csv_path, exc, exc_info=True
        )


# =============================================================================
# SECTION 6 — Dataset-Level Ingestion Pipelines  (Directory Traversal)
# =============================================================================
# Each pipeline function:
#   1. Validates that the directory exists and contains *.csv files.
#   2. Sorts files deterministically (alphabetical / chronological by name).
#   3. Applies an optional file ceiling (development mode).
#   4. Streams each file's chunks through the appropriate mapper.
#   5. Attempts Pydantic validation on each translated row.
#   6. Drops corrupted rows to stderr and continues — never halts the pipeline.
# =============================================================================

def _resolve_csv_files(directory: Path, file_limit: Optional[int]) -> list[Path]:
    """
    Safely enumerate *.csv files inside *directory* and apply an optional cap.

    Returns an empty list (with a log warning) if the directory is missing or
    contains no CSV files, rather than raising an exception.

    Args:
        directory:  Target directory path.
        file_limit: If set, return at most this many files.

    Returns:
        Sorted list of Path objects pointing to discovered CSV files.
    """
    if not directory.exists():
        logger.warning("Directory not found     : %s", directory)
        logger.warning("  → Skipping dataset ingestion for this path.")
        return []

    if not directory.is_dir():
        logger.error("Path is not a directory : %s", directory)
        return []

    files = sorted(directory.glob("*.csv"))

    if not files:
        logger.warning("No *.csv files found in : %s", directory)
        return []

    if file_limit is not None:
        original_count = len(files)
        files = files[:file_limit]
        logger.info(
            "File cap applied        : %d of %d CSV files selected from %s",
            len(files), original_count, directory,
        )

    return files


def ingest_ids2018_directory(
    directory: Path,
    file_limit: Optional[int] = None,
    row_limit_per_file: Optional[int] = None,
) -> Generator[UnifiedSecurityLog, None, None]:
    """
    Full CIC-IDS2018 ingestion pipeline.

    Traversal order:
        directory/*.csv  (sorted)
          └─ chunks of CHUNK_SIZE rows
               └─ _sanitize_row_dict(row)
                    └─ parse_ids2018_row(row)
                         └─ UnifiedSecurityLog(**mapped)   ← yield on success
                              └─ ValidationError           ← log to stderr, skip

    Args:
        directory:          Path to the CIC-IDS2018 dataset directory.
        file_limit:         Process at most this many CSV files (None = all).
        row_limit_per_file: Read at most this many rows per file (None = all).

    Yields:
        Validated UnifiedSecurityLog instances, one per well-formed row.
    """
    csv_files = _resolve_csv_files(directory, file_limit)
    logger.info(
        "IDS2018 pipeline start  : %d file(s) to process from %s",
        len(csv_files), directory,
    )

    for csv_file in csv_files:
        logger.info("IDS2018 → %s", csv_file.name)
        records_ok   = 0
        records_drop = 0

        for chunk in stream_csv_chunks(csv_file, row_limit=row_limit_per_file):
            for _, series in chunk.iterrows():
                # Step 1: Global NaN/inf/None scrub
                raw_row = _sanitize_row_dict(series.to_dict())
                # Step 2: Dataset-specific column mapping & unit normalisation
                mapped  = parse_ids2018_row(raw_row)
                # Step 3: Pydantic contract validation
                try:
                    yield UnifiedSecurityLog(**mapped)
                    records_ok += 1
                except ValidationError as exc:
                    records_drop += 1
                    _val_logger.warning(
                        "IDS2018 | DROPPED row in %s — %s",
                        csv_file.name,
                        exc.errors(include_url=False),
                    )

        logger.info(
            "IDS2018 ✓ %s : accepted=%d  dropped=%d",
            csv_file.name, records_ok, records_drop,
        )


def ingest_doh2020_directory(
    directory: Path,
    file_limit: Optional[int] = None,
    row_limit_per_file: Optional[int] = None,
) -> Generator[UnifiedSecurityLog, None, None]:
    """
    Full CIC-DoHBrw-2020 ingestion pipeline.

    Mirrors the IDS2018 pipeline structure but routes each row through
    parse_doh2020_row (seconds→µs conversion, port 443 defaulting, etc.).

    Args:
        directory:          Path to the CIC-DoHBrw-2020 dataset directory.
        file_limit:         Process at most this many CSV files (None = all).
        row_limit_per_file: Read at most this many rows per file (None = all).

    Yields:
        Validated UnifiedSecurityLog instances, one per well-formed row.
    """
    csv_files = _resolve_csv_files(directory, file_limit)
    logger.info(
        "DoH2020 pipeline start  : %d file(s) to process from %s",
        len(csv_files), directory,
    )

    for csv_file in csv_files:
        logger.info("DoH2020 → %s", csv_file.name)
        records_ok   = 0
        records_drop = 0

        for chunk in stream_csv_chunks(csv_file, row_limit=row_limit_per_file):
            for _, series in chunk.iterrows():
                raw_row = _sanitize_row_dict(series.to_dict())
                mapped  = parse_doh2020_row(raw_row)
                try:
                    yield UnifiedSecurityLog(**mapped)
                    records_ok += 1
                except ValidationError as exc:
                    records_drop += 1
                    _val_logger.warning(
                        "DoH2020 | DROPPED row in %s — %s",
                        csv_file.name,
                        exc.errors(include_url=False),
                    )

        logger.info(
            "DoH2020 ✓ %s : accepted=%d  dropped=%d",
            csv_file.name, records_ok, records_drop,
        )


# =============================================================================
# SECTION 7 — Test Execution Main Loop
# =============================================================================
# In TEST MODE (the defaults below) the script:
#   • Processes only the first MAX_FILES_PER_DATASET CSV files per dataset
#   • Reads only the first MAX_ROWS_PER_FILE data rows from each file
#   • Prints every validated UnifiedSecurityLog as indented JSON to stdout
#
# To run a full production ingest, set both limits to None.
# =============================================================================

if __name__ == "__main__":

    # ─────────────────────────────────────────────────────────────────────────
    # CONFIGURE: Replace these paths with your actual dataset directories.
    # Both may reside on the same storage volume or separate mounts.
    # ─────────────────────────────────────────────────────────────────────────
    DIR_IDS2018: Path = Path("/Volumes/Expansion/CyberML_Dataset/archive")
    DIR_DOH2020: Path = Path("/Volumes/Expansion/CyberML_Dataset/CSVs/Total_CSVs")

    # ─────────────────────────────────────────────────────────────────────────
    # TEST-MODE LIMITS
    # MAX_FILES_PER_DATASET = 2    → read the first 2 *.csv files per dataset
    # MAX_ROWS_PER_FILE     = 5    → read the first 5 data rows per file
    # Set either to None for a full production ingest (no limits).
    # ─────────────────────────────────────────────────────────────────────────
    MAX_FILES_PER_DATASET: int = 2
    MAX_ROWS_PER_FILE:     int = 5

    _SEP  = "═" * 72
    _THIN = "─" * 72

    print(_SEP)
    print("  PHASE 1 — DATA CONTRACTS & INGESTION ENGINE")
    print("  Autonomous Multi-Agent Threat Intelligence System")
    print(_THIN)
    print(f"  Mode          : TEST (limits active)")
    print(f"  File cap      : {MAX_FILES_PER_DATASET} CSV file(s) per dataset")
    print(f"  Row cap       : {MAX_ROWS_PER_FILE} row(s) per file")
    print(f"  IDS2018 dir   : {DIR_IDS2018.resolve()}")
    print(f"  DoH2020  dir  : {DIR_DOH2020.resolve()}")
    print(_SEP)

    # ── CIC-IDS2018 ──────────────────────────────────────────────────────────
    print("\n▶  CIC-IDS2018 — Validated UnifiedSecurityLog Records")
    print(_THIN)

    ids_total = 0
    for log_record in ingest_ids2018_directory(
        DIR_IDS2018,
        file_limit=MAX_FILES_PER_DATASET,
        row_limit_per_file=MAX_ROWS_PER_FILE,
    ):
        print(log_record.model_dump_json(indent=2))
        print(_THIN)
        ids_total += 1

    print(f"\n  ✔  IDS2018 records emitted : {ids_total}")

    # ── CIC-DoHBrw-2020 ──────────────────────────────────────────────────────
    print("\n▶  CIC-DoHBrw-2020 — Validated UnifiedSecurityLog Records")
    print(_THIN)

    doh_total = 0
    for log_record in ingest_doh2020_directory(
        DIR_DOH2020,
        file_limit=MAX_FILES_PER_DATASET,
        row_limit_per_file=MAX_ROWS_PER_FILE,
    ):
        print(log_record.model_dump_json(indent=2))
        print(_THIN)
        doh_total += 1

    print(f"\n  ✔  DoH2020 records emitted : {doh_total}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print(_SEP)
    print(f"  PIPELINE COMPLETE")
    print(f"  Total validated records  :  {ids_total + doh_total}")
    print(f"    IDS2018                :  {ids_total}")
    print(f"    DoH2020                :  {doh_total}")
    print(_SEP)
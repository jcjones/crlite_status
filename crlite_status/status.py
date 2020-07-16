#!/usr/bin/env python3

import argparse
import io
import itertools
import json
import re
import requests
import urllib
from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console
from rich.table import Table

kIdentifierFormat = re.compile(r"(\d{8}-\d+)/?")

parser = argparse.ArgumentParser()
parser.add_argument("count", help="Number of entries", type=int)
parser.add_argument("--crl", help="Evaluate CRL audits", action="store_true")
parser.add_argument("--crl-details", help="Path for HTML details", type=Path)
parser.add_argument(
    "--bucket-url",
    default="https://storage.googleapis.com/storage/v1/b/crlite_filters_staging/",
)
parser.add_argument(
    "--auditdb",
    help="Path to store CRL audits",
    type=Path,
    default=Path("~/.crlite_db/audits/"),
)


class FileNotFoundException(Exception):
    pass


def _item_to_value(iterator, item):
    return item


def list_google_storage_directories(base_url):
    params = {"projection": "noAcl", "delimiter": "/"}
    resp = requests.get(urllib.parse.urljoin(base_url, "o"), params=params)
    resp.raise_for_status()

    return resp.json()["prefixes"]


def normalize_identifier(s):
    """ The first part of the identifier is a date with no separators and is
        obvious to sort. The second part is a number which is generally a
        single digit, but in a degenerate case could end up with multiple, so
        we pad it here.
    """
    parts = s.rstrip("/").split("-")
    return f"{parts[0]}{int(parts[1]):06d}"


def get_run_identifiers(base_url, *, count=2):
    dirs = list_google_storage_directories(base_url)
    identifiers = filter(lambda x: kIdentifierFormat.match(x), dirs)
    identifiers = map(lambda x: kIdentifierFormat.match(x).group(1), identifiers)
    return reversed(
        list(sorted(identifiers, key=normalize_identifier, reverse=True))[:count]
    )


def _get_remote_path(base_url, remote_path, params):
    path_part = "o/" + urllib.parse.quote(str(remote_path), safe="")
    resp = requests.get(urllib.parse.urljoin(base_url, path_part), params=params)
    if resp.status_code == 404:
        raise FileNotFoundException(f"{remote_path} does not exist")
    resp.raise_for_status()
    return resp


def download_from_google_cloud_to_string(base_url, remote_path):
    params = {"alt": "media"}
    resp = _get_remote_path(base_url, remote_path, params)
    return resp.text


def download_from_google_cloud(base_url, remote_path, local_path):
    params = {"alt": "media"}
    resp = _get_remote_path(base_url, remote_path, params)

    with local_path.open("wb") as fd:
        for chunk in resp.iter_content(chunk_size=1024):
            fd.write(chunk)


def metadata_from_google_cloud(base_url, remote_path):
    params = {"alt": "json"}
    resp = _get_remote_path(base_url, remote_path, params)
    return resp.json()


def is_important_crl_audit_entry(entry):
    return entry["Kind"] not in ["Empty Revocation List"]


def size_to_str(sz_str):
    sz = int(sz_str)
    if sz > 1024 * 1024:
        return f"{sz/(1024*1024):,.3f} MB"
    if sz > 1024:
        return f"{sz/1024:,.3f} kB"
    return f"{sz:,} B"


def is_enrolled(issuer_subject, *, runinfo={}):
    if "enrolled" not in runinfo:
        return "Unknown"
    for issuer in runinfo["enrolled"]:
        if issuer_subject == issuer["pubKeyHash"]:
            if issuer["enrolled"]:
                return "✅"
            return "❌"
    return "Not Found"


def main():
    args = parser.parse_args()

    console = Console()

    run_info = {}

    previous_timestamp = None

    for run_id in get_run_identifiers(args.bucket_url, count=args.count):
        run_data = {
            "filter_size": None,
            "stash_size": None,
            "crl_audit": None,
            "filter_layers": None,
            "knownrevoked": None,
            "knownnotrevoked": None,
            "timestamp": None,
            "coverage_period": None,
        }
        stats = json.loads(
            download_from_google_cloud_to_string(
                args.bucket_url, Path(run_id) / "mlbf" / "stats.json"
            )
        )
        run_data["filter_layers"] = f"{stats['mlbf_layers']}"

        if "knownrevoked" in stats:
            run_data["knownrevoked"] = f"{stats['knownrevoked']:,}"

        if "knownnotrevoked" in stats:
            run_data["knownnotrevoked"] = f"{stats['knownnotrevoked']:,}"

        if "mlbf_filesize" in stats:
            run_data["filter_size"] = size_to_str(stats["mlbf_filesize"])
        else:
            filter_metadata = metadata_from_google_cloud(
                args.bucket_url, Path(run_id) / "mlbf" / "filter"
            )
            run_data["filter_size"] = size_to_str(filter_metadata["size"])

        if "stash_filesize" in stats:
            run_data["stash_size"] = size_to_str(stats["stash_filesize"])
        else:
            try:
                stash_metadata = metadata_from_google_cloud(
                    args.bucket_url, Path(run_id) / "mlbf" / "filter.stash"
                )
                run_data["stash_size"] = size_to_str(stash_metadata["size"])
            except FileNotFoundException:
                pass

        ts = datetime.fromisoformat(
            download_from_google_cloud_to_string(
                args.bucket_url, Path(run_id) / "timestamp"
            )
        ).replace(tzinfo=timezone.utc)
        run_data["timestamp"] = ts
        if previous_timestamp:
            run_data["coverage_period"] = str(ts - previous_timestamp)
        previous_timestamp = ts

        if args.crl or args.crl_details:
            audit_dir_local = args.auditdb.expanduser()
            audit_dir_local.mkdir(exist_ok=True, parents=True)
            local_audit_path = audit_dir_local / f"{run_id}-crl-audit.json"
            try:
                if not local_audit_path.is_file():
                    download_from_google_cloud(
                        args.bucket_url,
                        Path(run_id) / "crl-audit.json",
                        local_audit_path,
                    )
            except FileNotFoundException:
                pass
            with local_audit_path.open("r") as jf:
                run_data["crl_audit"] = json.load(jf)

            local_enrolled_path = audit_dir_local / f"{run_id}-enrolled.json"
            try:
                if not local_enrolled_path.is_file():
                    download_from_google_cloud(
                        args.bucket_url,
                        Path(run_id) / "enrolled.json",
                        local_enrolled_path,
                    )
            except FileNotFoundException:
                pass
            with local_enrolled_path.open("r") as jf:
                run_data["enrolled"] = json.load(jf)

        run_info[run_id] = run_data

    all_runs = sorted(run_info.keys(), key=normalize_identifier, reverse=True)

    size_table = Table(title="Recent Run Data", show_header=True)
    size_table.add_column("Run ID")
    size_table.add_column("Run Time")
    size_table.add_column("Filter")
    size_table.add_column("Filter Layers")
    size_table.add_column("Stash")
    size_table.add_column("Known Revoked")
    size_table.add_column("Known Not Revoked")
    size_table.add_column("Period Covered")
    previous_timestamp = None
    for run_id in all_runs:

        size_table.add_row(
            run_id,
            f"{run_info[run_id]['timestamp']:%Y-%m-%d %H:%M}Z",
            run_info[run_id]["filter_size"],
            run_info[run_id]["filter_layers"],
            run_info[run_id]["stash_size"],
            run_info[run_id]["knownrevoked"],
            run_info[run_id]["knownnotrevoked"],
            run_info[run_id]["coverage_period"],
        )
    console.print(size_table)

    if args.crl or args.crl_details:
        detail_console = Console(file=io.StringIO(), record=True)

        for run_id in all_runs:
            issuer_to_crl_audit = {}
            for entry in filter(
                is_important_crl_audit_entry, run_info[run_id]["crl_audit"]["Entries"]
            ):
                if entry["IssuerSubject"] not in issuer_to_crl_audit:
                    issuer_to_crl_audit[entry["IssuerSubject"]] = []
                issuer_to_crl_audit[entry["IssuerSubject"]].append(entry)

            table = Table(title=f"{run_id} CRL Audit Entries", show_header=True)
            table.add_column("Issuer")
            table.add_column("Kind")
            table.add_column("Count")
            table.add_column("Enrolled")

            detail_console.rule(f"{run_id} CRL Audit Entries")

            for issuerSubject in issuer_to_crl_audit:
                for kind, entries in itertools.groupby(
                    sorted(issuer_to_crl_audit[issuerSubject], key=lambda x: x["Kind"]),
                    key=lambda x: x["Kind"],
                ):
                    entries_list = list(entries)
                    num_entries = len(entries_list)
                    first_entry = entries_list[0]
                    table.add_row(
                        issuerSubject,
                        kind,
                        str(num_entries),
                        is_enrolled(first_entry["Issuer"], runinfo=run_info[run_id]),
                    )

                for entry in issuer_to_crl_audit[issuerSubject]:
                    detail_console.print(entry)

            console.print(table)
            detail_console.print(table)

        if args.crl_details:
            console.log(f"Writing CRL details to {args.crl_details}")
            detail_console.save_html(args.crl_details)


if __name__ == "__main__":
    main()

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
crl_group = parser.add_argument_group(
    title="Evaluate CRLs", description="Download CRL audit data and analyze it"
)
crl_group.add_argument("--crl", help="Evaluate CRL audits", action="store_true")
crl_group.add_argument("--crl-details", help="Path for HTML details", type=Path)
crl_group.add_argument(
    "--crl-details-all",
    help="Print details for every CRL, even trivially valid ones",
    action="store_true",
)
crl_group.add_argument(
    "--auditdb",
    help="Path to store CRL audits",
    type=Path,
    default=Path("~/.crlite_db/audits/"),
)
group = parser.add_mutually_exclusive_group()
group.add_argument(
    "--bucket-url",
    default="https://storage.googleapis.com/storage/v1/b/crlite-filters-prod/",
)
group.add_argument(
    "--stage",
    action="store_true",
    help="Read from the Stage environment",
)


def get_bucket_url(args):
    if args.stage:
        return "https://storage.googleapis.com/storage/v1/b/crlite-filters-stage/"
    return args.bucket_url


class FileNotFoundException(Exception):
    pass


def _item_to_value(iterator, item):
    return item


def list_google_storage_directories(base_url):
    pageToken = None
    dirs = []
    while True:
        params = {"projection": "noAcl", "delimiter": "/"}
        if pageToken:
            params["pageToken"] = pageToken

        resp = requests.get(urllib.parse.urljoin(base_url, "o"), params=params)
        resp.raise_for_status()
        data = resp.json()
        dirs.extend(data["prefixes"])

        if "nextPageToken" not in data:
            return dirs
        pageToken = data["nextPageToken"]


def normalize_identifier(s):
    """The first part of the identifier is a date with no separators and is
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


def is_enrolled(issuerPubKeyHash, *, runinfo={}):
    if "enrolled" not in runinfo:
        return "Unknown"
    for issuer in runinfo["enrolled"]:
        if issuerPubKeyHash == issuer["pubKeyHash"]:
            if issuer["enrolled"]:
                return "✅"
            return "❌"
    return "Not Found"


def main():
    args = parser.parse_args()

    console = Console()

    run_info = {}

    previous_timestamp = None

    for run_id in get_run_identifiers(get_bucket_url(args), count=args.count):
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
                get_bucket_url(args), Path(run_id) / "mlbf" / "stats.json"
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
                get_bucket_url(args), Path(run_id) / "mlbf" / "filter"
            )
            run_data["filter_size"] = size_to_str(filter_metadata["size"])

        if "stash_filesize" in stats:
            run_data["stash_size"] = size_to_str(stats["stash_filesize"])
            run_data["stash_num_issuers"] = str(stats["stash_num_issuers"])
        else:
            try:
                stash_metadata = metadata_from_google_cloud(
                    get_bucket_url(args), Path(run_id) / "mlbf" / "filter.stash"
                )
                run_data["stash_size"] = size_to_str(stash_metadata["size"])
                run_data["stash_num_issuers"] = "n/a"
            except FileNotFoundException:
                pass

        ts = datetime.fromisoformat(
            download_from_google_cloud_to_string(
                get_bucket_url(args), Path(run_id) / "timestamp"
            )
        ).replace(tzinfo=timezone.utc)
        run_data["timestamp"] = ts
        if previous_timestamp:
            run_data["coverage_period"] = str(ts - previous_timestamp)
        previous_timestamp = ts

        audit_dir_local = args.auditdb.expanduser()
        audit_dir_local.mkdir(exist_ok=True, parents=True)
        local_audit_path = audit_dir_local / f"{run_id}-crl-audit.json"
        try:
            if not local_audit_path.is_file():
                download_from_google_cloud(
                    get_bucket_url(args),
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
                    get_bucket_url(args),
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
    size_table.add_column("Enrolled Issuers")
    size_table.add_column("Stash")
    size_table.add_column("Known Revoked")
    size_table.add_column("Known Not Revoked")
    size_table.add_column("Period Covered")
    previous_timestamp = None
    for run_id in all_runs:
        if "enrolled" in run_info[run_id]:
            enrolled_len = str(
                len(list(filter(lambda x: x["enrolled"], run_info[run_id]["enrolled"])))
            )
        else:
            enrolled_len = "n/a"

        size_table.add_row(
            run_id,
            f"{run_info[run_id]['timestamp']:%Y-%m-%d %H:%M}Z",
            run_info[run_id]["filter_size"],
            run_info[run_id]["filter_layers"],
            enrolled_len,
            f"{run_info[run_id]['stash_size']} ({run_info[run_id]['stash_num_issuers']} issuers)",
            run_info[run_id]["knownrevoked"],
            run_info[run_id]["knownnotrevoked"],
            run_info[run_id]["coverage_period"],
        )
    console.print(size_table)

    if args.crl or args.crl_details or args.crl_details_all:
        summary_tables = list()
        detail_console = Console(file=io.StringIO(), record=True)

        for run_id in all_runs:
            issuer_to_crl_audit = {}
            for entry in filter(
                is_important_crl_audit_entry, run_info[run_id]["crl_audit"]["Entries"]
            ):
                if entry["IssuerSubject"] not in issuer_to_crl_audit:
                    issuer_to_crl_audit[entry["IssuerSubject"]] = {
                        "crls": [],
                        "issuerPubKeyHash": entry["Issuer"],
                    }
                issuer_to_crl_audit[entry["IssuerSubject"]]["crls"].append(entry)

            table = Table(
                title=f"{run_id} CRL Audit Entries by Issuer/Status", show_header=True
            )
            table.add_column("Issuer")
            table.add_column("Enrolled")
            table.add_column("Number of Failed CRLs")
            table.add_column("Number of Recovered CRLs")
            table.add_column("Number of Updated CRLs")
            table.add_column("Number of CRLs")

            detail_console.rule(f"{run_id} CRL Audit Entries")

            for issuerSubject in issuer_to_crl_audit:
                enrolled = is_enrolled(
                    issuer_to_crl_audit[issuerSubject]["issuerPubKeyHash"],
                    runinfo=run_info[run_id],
                )

                # for kind, crls in itertools.groupby(
                #     sorted(
                #         issuer_to_crl_audit[issuerSubject]["crls"],
                #         key=lambda x: x["Kind"],
                #     ),
                #     key=lambda x: x["Kind"],
                # ):
                #     num_entries = len(list(crls))
                #     table.add_row(
                #         issuerSubject,
                #         kind,
                #         enrolled,
                #         str(num_entries),
                #     )

                num_failed = 0
                num_recovered = 0
                num_updated = 0
                num_total = 0

                issuer_table = Table(
                    title=f"{issuerSubject} CRLs - {enrolled}", show_header=True
                )
                issuer_table.add_column("URL")
                issuer_table.add_column("Statuses")
                issuer_table.add_column("Details")

                for url, entries_grp in itertools.groupby(
                    issuer_to_crl_audit[issuerSubject]["crls"], key=lambda x: x["Url"]
                ):
                    num_total += 1

                    entries = list(entries_grp)
                    statuses = list(map(lambda x: x["Kind"], entries))

                    if "Valid, Processed" in statuses:
                        if len(statuses) == 1:
                            num_updated += 1
                        else:
                            num_recovered += 1
                    else:
                        num_failed += 1

                    if (
                        len(statuses) == 1
                        and "Valid, Processed" in statuses
                        and not args.crl_details_all
                    ):
                        continue

                    issuer_table.add_row(
                        url,
                        f"{statuses}",
                        f"{entries}",
                    )
                    detail_console.print(issuer_table)

                table.add_row(
                    issuerSubject,
                    enrolled,
                    f"{num_failed}",
                    f"{num_recovered}",
                    f"{num_updated}",
                    f"{num_total}",
                )

            console.print(table)
            summary_tables.append(table)

        if args.crl_details:
            console.log(f"Writing CRL details to {args.crl_details}")
            detail_console.rule(f"Summary Tables")
            for table in summary_tables:
                detail_console.print(table)
            detail_console.save_html(args.crl_details)


if __name__ == "__main__":
    main()

from argparse import ArgumentParser
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import re
from struct import unpack
import yaml


def get_cli_args():
    argparser = ArgumentParser()
    argparser.add_argument(
        "--config",
        help="ACTOS config file to use for flight processing",
        required=True,
        type=Path,
    )
    argparser.add_argument(
        "--flights",
        nargs="+",
        help="List of ACTOS pcap file directories to process",
        required=True,
        type=Path,
    )
    argparser.add_argument(
        "--output",
        help="Optional non-default output directory for decoded flight data",
        required=False,
        type=Path,
    )
    return argparser.parse_args()


def get_config(config_path):
    with open(config_path, "r") as config_file:
        return yaml.safe_load(config_file)


cli_args = get_cli_args()
flight_cfg = get_config(cli_args.config)


def get_pcap_files(flight):
    yield from sorted(flight.glob("*.cap"))


def get_udp_packets(pcap_file):
    with open(pcap_file, "rb") as pcap_file:
        pcap_file.read(24)
        while True:
            pcap_header = pcap_file.read(16)
            if not pcap_header:
                break
            pcap_length = unpack("<I", pcap_header[8:12])[0]
            yield pcap_file.read(pcap_length)


ptp_format = flight_cfg["defaults"]["timestamp_format"]


def parse_ptp(ptp_raw, ptp_format):
    seconds, nanoseconds = unpack(">2I", ptp_raw)
    ptp = datetime.fromtimestamp(seconds) + timedelta(microseconds=nanoseconds / 1000)
    return datetime.strftime(ptp, ptp_format)


def reassamble_fragmented_telegrams(packets_per_telegram, telegrams):
    for i in range(0, len(telegrams), packets_per_telegram):
        payload = b"".join(
            telegrams[i + j].payload for j in range(packets_per_telegram)
        )
        yield Telegram(ptp=telegrams[i].ptp, payload=payload)


def format_for_raw_export(telegrams):
    yield from ((parse_ptp(t.ptp, ptp_format), t.payload.hex()) for t in telegrams)


def decode(sid, telegrams):
    if "packets_per_telegram" in flight_cfg[sid]:
        telegrams = reassamble_fragmented_telegrams(
            flight_cfg[sid]["packets_per_telegram"], telegrams
        )
    # if "export_raw_data" in flight_cfg[sid]:
    #     yield from ((parse_ptp(t.ptp, ptp_format), t.payload.hex()) for t in telegrams)
    if flight_cfg[sid]["encoding"] == "ascii":
        yield from decode_ascii(sid, telegrams)
    if flight_cfg[sid]["encoding"] == "binary":
        yield from decode_binary(sid, telegrams)


def decode_ascii(sid, telegrams):
    yield from (
        Telegram(
            ptp=parse_ptp(t.ptp, ptp_format),
            payload=t.payload.decode("ascii", errors="ignore"),
        )
        for t in telegrams
    )


def clean_ascii(sid, telegrams):
    pattern = re.compile("|".join(flight_cfg[sid]["cleaning_regex"]))
    dedublicate_commas = re.compile(r",+")
    for t in telegrams:
        cleaned_payload = pattern.sub(",", t.payload)
        cleaned_payload = dedublicate_commas.sub(",", cleaned_payload).strip(",")
        parameter_list = cleaned_payload.split(",")
        yield (t.ptp, *parameter_list)


def decode_binary(sid, telegrams):
    fmt = flight_cfg[sid]["binary_format"]
    commutation_factor = flight_cfg[sid].get("commutation_factor")
    analog = True if "voltage_ranges" in flight_cfg[sid] else False
    ranges = flight_cfg[sid].get("voltage_ranges")
    scale = 1 / (2**16 - 1) if analog else None
    for t in telegrams:
        ptp = parse_ptp(t.ptp, ptp_format)
        decoded_telegram = unpack(fmt, t.payload)
        if commutation_factor:
            for i in range(commutation_factor):
                sub_telegrams = decoded_telegram[i::commutation_factor]
                if analog:
                    sub_telegrams = tuple(
                        v * scale * (vmax - vmin) + vmin
                        for v, (vmin, vmax) in zip(sub_telegrams, ranges)
                    )
                yield (ptp if i == 0 else None, *sub_telegrams)
        elif analog:
            converted_telegram = tuple(
                v * scale * (vmax - vmin) + vmin
                for v, (vmin, vmax) in zip(decoded_telegram, ranges)
            )
            yield (ptp, *converted_telegram)
        else:
            yield (ptp, *decoded_telegram)


@dataclass
class Telegram:
    ptp: bytes
    payload: bytes


def save_to_csv(flight, sid, decoded_stream_telegrams):
    outdir = cli_args.output or flight.parent / flight_cfg["defaults"]["output_subdir"]
    outdir.mkdir(exist_ok=True)
    outpath = outdir / f"{sid}_{flight_cfg[sid]['name']}.csv"
    with open(outpath, "w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(
            [
                flight_cfg["defaults"]["timestamp_name"],
                *flight_cfg[sid]["parameters"],
            ]
        )
        writer.writerows(decoded_stream_telegrams)

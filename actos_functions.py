from argparse import ArgumentParser
from construct import (
    Adapter,
    Bytes,
    Float32l,
    Float32b,
    Float64l,
    Float64b,
    Int8ul,
    Int8ub,
    Int16ul,
    Int16ub,
    Int32ul,
    Int32ub,
    Sequence,
)
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import re
from struct import unpack
from typing import List
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


@dataclass
class Telegram:
    ptp: bytes | datetime
    payload: bytes | List[int | float]


ptp_format = flight_cfg["defaults"]["timestamp_format"]


def parse_ptp(ptp_raw, ptp_format):
    seconds, nanoseconds = unpack(">2I", ptp_raw)
    ptp = datetime.fromtimestamp(seconds) + timedelta(microseconds=nanoseconds / 1000)
    return datetime.strftime(ptp, ptp_format)


def reassamble_fragmented_telegrams(udp_packets_per_telegram, telegrams):
    len_telegrams = len(telegrams) - len(telegrams) % udp_packets_per_telegram
    for i in range(0, len_telegrams, udp_packets_per_telegram):
        payload = b"".join(
            telegrams[i + j].payload for j in range(udp_packets_per_telegram)
        )
        yield Telegram(ptp=telegrams[i].ptp, payload=payload)


def format_for_raw_export(telegrams):
    for t in telegrams:
        yield Telegram(ptp=parse_ptp(t.ptp, ptp_format), payload=[t.payload.hex()])


def decode_ascii(telegrams):
    for t in telegrams:
        yield Telegram(
            ptp=parse_ptp(t.ptp, ptp_format),
            payload=t.payload.decode("ascii", errors="ignore"),
        )


def clean_ascii(sid, telegrams):
    pattern = re.compile("|".join(flight_cfg[sid]["cleaning_regex"]))
    dedublicate_commas = re.compile(r",+")
    for t in telegrams:
        cleaned_payload = pattern.sub(",", t.payload)
        cleaned_payload = dedublicate_commas.sub(",", cleaned_payload).strip(",")
        parameter_list = cleaned_payload.split(",")
        yield Telegram(ptp=t.ptp, payload=parameter_list)


class WordSwap16(Adapter):
    def _decode(self, obj, context, path):
        swapped = b"".join(obj[i : i + 2][::-1] for i in range(0, len(obj), 2))
        return int.from_bytes(swapped, "big")


class Packed12_20(Adapter):
    def _decode(self, obj, context, path):
        return {
            "u12": obj >> 20,
            "u20": obj & 0xFFFFF,
        }


UInt16Mixed = WordSwap16(Bytes(2))
UInt32Mixed = WordSwap16(Bytes(4))
UInt48Mixed = WordSwap16(Bytes(6))
Packed12_20Mixed = Packed12_20(UInt32Mixed)


config_to_construct_type_map = {
    "little": {
        "uint8": Int8ul,
        "uint16": Int16ul,
        "uint32": Int32ul,
        "float32": Float32l,
        "float64": Float64l,
    },
    "big": {
        "uint8": Int8ub,
        "uint16": Int16ub,
        "uint32": Int32ub,
        "float32": Float32b,
        "float64": Float64b,
    },
    "word_swap_16": {
        "uint16": UInt16Mixed,
        "uint32": UInt32Mixed,
        "uint48": UInt48Mixed,
        "packed12_20": Packed12_20Mixed,
    },
}


def build_binary_parser(sid):
    types = config_to_construct_type_map[flight_cfg[sid]["endian"]]
    fields = []
    for item in flight_cfg[sid]["binary_schema"]:
        if "*" in item:
            typename, count = item.split("*")
            subcon = types[typename][int(count)]
        else:
            subcon = types[item]
        fields.append(subcon)
    return Sequence(*fields)


def flatten_payload(payload):
    row = []
    for item in payload:
        if isinstance(item, (list, tuple)):
            row.extend(flatten_payload(item))
        elif isinstance(item, dict):
            row.extend(flatten_payload(item.values()))
        else:
            row.append(item)
    return row


def decode_binary(sid, telegrams):
    parser = build_binary_parser(sid)
    for t in telegrams:
        yield Telegram(
            ptp=parse_ptp(t.ptp, ptp_format),
            payload=flatten_payload(parser.parse(t.payload)),
        )


def decommutate_telegrams(sid, telegrams):
    commutation_factor = flight_cfg[sid].get("commutation_factor")
    for t in telegrams:
        for i in range(commutation_factor):
            yield Telegram(
                ptp=t.ptp if i == 0 else None, payload=t.payload[i::commutation_factor]
            )


def convert_ints_to_voltages(sid, telegrams):
    voltage_ranges = flight_cfg[sid].get("voltage_ranges")
    scale = 1 / (2**16 - 1)
    for t in telegrams:
        payload = (
            (v * scale * (vmax - vmin) + vmin)
            for v, (vmin, vmax) in zip(t.payload, voltage_ranges)
        )
        yield Telegram(ptp=t.ptp, payload=payload)


def save_to_csv(flight, sid, telegrams):
    outdir = cli_args.output or flight.parent / flight_cfg["defaults"]["output_subdir"]
    outdir.mkdir(exist_ok=True)
    outpath = outdir / f"{sid}_{flight_cfg[sid]['name']}.csv"
    with outpath.open("w", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(
            [
                flight_cfg["defaults"]["timestamp_name"],
                *flight_cfg[sid]["parameters"],
            ]
        )
        for t in telegrams:
            writer.writerow((t.ptp, *t.payload))

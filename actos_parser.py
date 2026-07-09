from actos_functions import *
from collections import defaultdict


def actos_parser():
    print("Starting ACTOS parser, yeaahhh!")

    cli_args = get_cli_args()
    flight_cfg = get_config(cli_args.config)

    for flight in cli_args.flights:
        print(f"Processing flight: {flight.resolve()}")

        flight_telegrams = defaultdict(list)
        for pcap_file in get_pcap_files(flight):
            for udp_packet in get_udp_packets(pcap_file):
                sid = udp_packet[47:50].hex()
                if sid not in flight_cfg:
                    continue
                telegram = Telegram(
                    ptp=udp_packet[58:66],
                    payload=udp_packet[80:]
                    if flight_cfg[sid]["packet_type"] == "packetizer"
                    else udp_packet[70:],
                    is_fragmented=udp_packet[78] >> 4 & 1
                    if flight_cfg[sid]["packet_type"] == "packetizer"
                    else None,
                )
                flight_telegrams[sid].append(telegram)

        for sid in sorted(flight_telegrams):
            print(f"Processing stream-id: {sid}")

            stream_telegrams = flight_telegrams[sid]
            if "udp_packets_per_telegram" in flight_cfg[sid]:
                stream_telegrams = reassamble_fragmented_telegrams(
                    flight_cfg[sid]["udp_packets_per_telegram"], stream_telegrams
                )
            if flight_cfg[sid].get("export_as_raw_data"):
                stream_telegrams = format_for_raw_export(stream_telegrams)
                save_to_csv(flight, sid, stream_telegrams)
                continue
            if flight_cfg[sid]["encoding"] == "ascii":
                stream_telegrams = decode_ascii(stream_telegrams)
                stream_telegrams = clean_ascii(sid, stream_telegrams)
            if flight_cfg[sid]["encoding"] == "binary":
                stream_telegrams = decode_binary(sid, stream_telegrams)
            if flight_cfg[sid].get("commutation_factor"):
                stream_telegrams = decommutate_telegrams(sid, stream_telegrams)
            if flight_cfg[sid].get("voltage_ranges"):
                stream_telegrams = convert_ints_to_voltages(sid, stream_telegrams)
            save_to_csv(flight, sid, stream_telegrams)

    print("Ex(c)iting ACTOS parser")


if __name__ == "__main__":
    actos_parser()

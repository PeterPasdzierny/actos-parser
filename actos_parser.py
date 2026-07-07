from actos_functions import *
from collections import defaultdict


def actos_parser():
    cli_args = get_cli_args()
    flight_cfg = get_config(cli_args.config)

    for flight in cli_args.flights:
        print(f"Processing flight {flight.name}")
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
                )
                flight_telegrams[sid].append(telegram)

        for sid in flight_telegrams:
            print(f"Processing stream {sid}")
            stream_telegrams = decode(sid, flight_telegrams[sid])
            save_to_csv(flight, sid, stream_telegrams)


if __name__ == "__main__":
    print("Starting ACTOS parser")
    actos_parser()
    print("Ex(c)iting ACTOS parser")

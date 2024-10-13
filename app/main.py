import json
import os
import sys
import hashlib
import requests
import random, math
import socket
import struct
import getopt
import urllib.parse
from typing import Any, List, Dict


class bencodeDecoder:
    def __init__(self, bencoded_value: bytes):
        self.bencoded_value = bencoded_value
        self.index = 0

    def decode(self) -> Any:
        return self._decode_types()

    def _decode_intgr(self) -> int:
        start_index = self.index + 1
        end_index = self.bencoded_value.find(b"e", start_index)
        if end_index == -1:
            raise ValueError("'e' isn't there. Invalid Integer")
        intgr_value = int(self.bencoded_value[start_index:end_index])
        self.index = end_index + 1
        return intgr_value

    def _decode_str(self) -> str:
        fst_index = self.bencoded_value.find(b":", self.index)
        if fst_index == -1:
            raise ValueError("':' isn't there. Invalid String")
        length = int(self.bencoded_value[self.index : fst_index])
        start_index = fst_index + 1
        end_index = start_index + length
        if end_index > len(self.bencoded_value):
            raise ValueError("More length error.")
        str_value = self.bencoded_value[start_index:end_index]
        self.index = end_index
        try:
            return str_value.decode("utf-8")
        except UnicodeDecodeError:
            return str_value

    def _decode_list(self) -> List[Any]:
        rst_list = []
        self.index += 1
        while self.index < len(self.bencoded_value) and self.bencoded_value[
            self.index
        ] != ord("e"):
            elem = self._decode_types()
            rst_list.append(elem)
        if self.index >= len(self.bencoded_value) or self.bencoded_value[
            self.index
        ] != ord("e"):
            raise ValueError("'e' missing.")
        self.index += 1
        return rst_list

    def _decode_dict(self) -> Dict[str, Any]:
        result_dict = {}
        self.index += 1
        while self.index < len(self.bencoded_value) and self.bencoded_value[
            self.index
        ] != ord("e"):
            key = self._decode_str()
            value = self._decode_types()
            result_dict[key] = value
        if self.index >= len(self.bencoded_value) or self.bencoded_value[
            self.index
        ] != ord("e"):
            raise ValueError("'e' missing. Invalid Dictionary")
        self.index += 1
        return result_dict

    def _decode_types(self) -> Any:
        if self.bencoded_value[self.index] == ord("i"):
            return self._decode_intgr()
        if self.bencoded_value[self.index] == ord("l"):
            return self._decode_list()
        if self.bencoded_value[self.index] == ord("d"):
            return self._decode_dict()
        elif chr(self.bencoded_value[self.index]).isdigit():
            return self._decode_str()
        else:
            raise NotImplementedError("Include Only Integers, String, Dict & List")


def bytes_to_str(data):
    if isinstance(data, bytes):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data
    raise TypeError(f"Type not serializable: {type(data)}")


def bencode(data) -> bytes:
    if isinstance(data, int):
        return b"i" + str(data).encode() + b"e"
    elif isinstance(data, bytes):
        return str(len(data)).encode() + b":" + data
    elif isinstance(data, str):
        data = data.encode("utf-8")
        return str(len(data)).encode() + b":" + data
    elif isinstance(data, list):
        return b"l" + b"".join(bencode(item) for item in data) + b"e"
    elif isinstance(data, dict):
        items = sorted(data.items())
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in items) + b"e"
    else:
        raise TypeError(f"Cannot bencode object of type {type(data)}")


def generate_peer_id() -> bytes:
    return b"-PC0001-" + bytes(random.randint(0, 255) for _ in range(12))


def calculate_info_hash(info: dict) -> bytes:
    return hashlib.sha1(bencode(info)).digest()


def formatted_pieces(pieces: bytes) -> list:
    return [pieces[i : i + 20].hex() for i in range(0, len(pieces), 20)]


def perform_handshake(peer_ip: str, peer_port: int, info_hash: bytes) -> bytes:
    peer_id = generate_peer_id()
    handshake_message = (
        bytes([19]) + b"BitTorrent protocol" + b"\x00" * 8 + info_hash + peer_id
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, peer_port))
        s.send(handshake_message)
        response = s.recv(68)
    received_peer_id = response[48:68]
    return received_peer_id


def discover_peers(torrent: dict, info_hash: bytes, peer_id: bytes) -> None:
    tracker_url = torrent["announce"]
    query_params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": random.randint(6881, 6889),
        "uploaded": 0,
        "downloaded": 0,
        "left": torrent["info"]["length"],
        "compact": 1,
        "event": "started",
    }
    url = tracker_url + "?" + urllib.parse.urlencode(query_params)
    response = requests.get(url)
    tracker_response = bencodeDecoder(response.content).decode()
    peers_binary = tracker_response["peers"]
    peers = []
    for i in range(0, len(peers_binary), 6):
        ip = ".".join(str(b) for b in peers_binary[i : i + 4])
        port = struct.unpack(">H", peers_binary[i + 4 : i + 6])[0]
        peers.append(f"{ip}:{port}")
    for peer in peers:
        print(peer)


def download_piece(
    torrent: dict, piece_index: int, peer_address: str, output_file: str
) -> None:
    peer_ip, peer_port = peer_address.split(":")
    peer_port = int(peer_port)
    piece_length = torrent["info"]["piece length"]
    total_blocks = (piece_length + (16 * 1024) - 1) // (16 * 1024)
    piece_hash = torrent["info"]["pieces"][piece_index * 20 : (piece_index + 1) * 20]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, peer_port))

        # Send handshake
        info_hash = calculate_info_hash(torrent["info"])
        peer_id = generate_peer_id()
        handshake_message = (
            bytes([19]) + b"BitTorrent protocol" + b"\x00" * 8 + info_hash + peer_id
        )
        s.send(handshake_message)

        # Receive handshake response
        s.recv(68) 
        interested_message = struct.pack("!I", 1) + struct.pack("!B", 2)
        s.send(interested_message)
        while True:
            response = s.recv(1024)
            if len(response) >= 5 and response[4] == 1:  # Unchoke message ID is 1
                break

        all_blocks_data = bytearray()
        for block_index in range(total_blocks):
            begin = block_index * (16 * 1024)
            block_length = min(16 * 1024, piece_length - begin)

            # Send 'request' message for each block
            request_message = (
                struct.pack("!I", 13)  # Message length (9 bytes for payload)
                + struct.pack("!B", 6)  # Request message ID is 6
                + struct.pack("!I", piece_index)  # Piece index
                + struct.pack("!I", begin)  # Block start offset
                + struct.pack("!I", block_length)  # Block length
            )
            s.send(request_message)
            piece_response = s.recv(1024 + 13)
            piece_id = piece_response[4]  # Check the piece message ID
            if piece_id == 7:  # Piece message ID is 7
                all_blocks_data.extend(piece_response[13:])

        # Validate the received piece's hash
        piece_hash_received = hashlib.sha1(all_blocks_data).digest()
        if piece_hash_received == piece_hash:
            with open(output_file, "wb") as f:
                f.write(all_blocks_data)
            print(f"Downloaded and verified piece {piece_index} to {output_file}")
        else:
            print(f"Piece {piece_index} failed integrity check!")


if __name__ == "__main__":
    command = sys.argv[1]
    if command == "decode":
        bencoded_inp = sys.argv[2].encode()
        decoder = bencodeDecoder(bencoded_inp)
        decoded_value = decoder.decode()
        print(json.dumps(decoded_value, default=bytes_to_str))
    elif command == "info":
        file_name = sys.argv[2]
        try:
            with open(file_name, "rb") as torrent_file:
                bencoded_content = torrent_file.read()
            decoder = bencodeDecoder(bencoded_content)
            torrent = decoder.decode()
            print("Tracker URL:", torrent["announce"])
            print("Length:", torrent["info"]["length"])
            info_hash = calculate_info_hash(torrent["info"])
            print("Info Hash:", info_hash.hex())
            piece_length = torrent["info"]["piece length"]
            print("Piece Length:", piece_length)
            piece_hashes = formatted_pieces(torrent["info"]["pieces"])
            print("Piece Hashes:")
            for piece_hash in piece_hashes:
                print(piece_hash)
        except FileNotFoundError:
            print(f"Error: File '{file_name}' not found.")
        except KeyError as e:
            print(f"Error: Missing expected field in torrent file: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    elif command == "peers":  
        file_name = sys.argv[2]
        try:
            with open(file_name, "rb") as torrent_file:
                bencoded_content = torrent_file.read()
                decoder = bencodeDecoder(bencoded_content)
                torrent = decoder.decode()
                info_hash = calculate_info_hash(torrent["info"])
                peer_id = generate_peer_id()  # Generate a new peer ID
                print(f"Peer ID: {peer_id.hex()}")
                print("Discovering peers...")
                discover_peers(torrent, info_hash, peer_id)  # Discover peers
        except FileNotFoundError:
            print(f"Error: File '{file_name}' not found.")
        except KeyError as e:
            print(f"Error: Missing expected field in torrent file: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    elif command == "handshake":
        file_name = sys.argv[2]
        peer_address = sys.argv[3].split(":")
        peer_ip = peer_address[0]
        peer_port = int(peer_address[1])
        try:
            with open(file_name, "rb") as torrent_file:
                bencoded_content = torrent_file.read()
                decoder = bencodeDecoder(bencoded_content)
                torrent = decoder.decode()
                info_hash = calculate_info_hash(torrent["info"])
                peer_id = perform_handshake(peer_ip, peer_port, info_hash)
                print(f"Peer ID: {peer_id.hex()}")
        except FileNotFoundError:
            print(f"Error: File '{file_name}' not found.")
        except KeyError as e:
            print(f"Error: Missing expected field in torrent file: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    elif command == "download_piece":
        output_file = None  # Initialize output_file
        file_name = None  # Initialize file_name
        piece_index = None  # Initialize piece_index
        peer_address = None  # Initialize peer_address

        # Parse the arguments based on expected order
        for i in range(2, len(sys.argv)):
            if sys.argv[i] == "-o":
                if i + 1 < len(sys.argv):
                    output_file = sys.argv[i + 1]
                else:
                    print("Error: No output file specified after -o.")
                    sys.exit(1)
            elif sys.argv[i].isdigit():
                try:
                    piece_index = int(sys.argv[i])
                except ValueError:
                    print(
                        f"Error: Invalid piece index '{sys.argv[i]}'. Must be an integer."
                    )
                    sys.exit(1)
            elif ":" in sys.argv[i]:
                peer_address = sys.argv[i]
            else:
                file_name = sys.argv[i]
        if (
            file_name is None
            or piece_index is None
            or output_file is None
            or peer_address is None
        ):
            print(
                "Error: Missing required parameters. Usage: ./your_bittorrent.sh download_piece -o <output_file> <torrent_file> <piece_index> <peer_address>"
            )
            sys.exit(1)

        try:
            with open(file_name, "rb") as torrent_file:
                bencoded_content = torrent_file.read()
                decoder = bencodeDecoder(bencoded_content)
                torrent = decoder.decode()
                download_piece(torrent, piece_index, peer_address, output_file)
        except FileNotFoundError:
            print(f"Error: File '{file_name}' not found.")
        except KeyError as e:
            print(f"Error: Missing expected field in torrent file: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

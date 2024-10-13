import json
import os
import sys
import hashlib
import requests
import random
import socket
import struct
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
    peer_id = generate_peer_id()  # Your generated peer ID
    handshake_message = (
        bytes([19])  # Length of "BitTorrent protocol"
        + b"BitTorrent protocol"  # Protocol string
        + b"\x00" * 8  # Reserved bytes
        + info_hash  # 20-byte info hash
        + peer_id  # Your 20-byte peer ID
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, peer_port))
        s.send(handshake_message)
        response = s.recv(68)  # Receive the handshake response

    received_peer_id = response[48:68]  # Extract peer ID
    return received_peer_id


def discover_peers(torrent: dict, info_hash: bytes, peer_id: bytes) -> None:
    tracker_url = torrent["announce"]
    query_params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": random.randint(6881, 6889),  # Random port
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


def send_message(s: socket.socket, msg_id: int, payload: bytes = b"") -> None:
    msg_length = struct.pack(">I", len(payload) + 1)
    s.send(msg_length + bytes([msg_id]) + payload)


def receive_message(s: socket.socket) -> (int, bytes):
    msg_length = struct.unpack(">I", s.recv(4))[0]
    if msg_length == 0:
        return -1, b""
    msg_id = s.recv(1)[0]
    payload = s.recv(msg_length - 1)
    return msg_id, payload


def download_piece(
    peer_ip: str,
    peer_port: int,
    info_hash: bytes,
    piece_index: int,
    piece_length: int,
    output_path: str,
):
    peer_id = generate_peer_id()  # Your generated peer ID
    handshake_message = (
        bytes([19])  # Length of "BitTorrent protocol"
        + b"BitTorrent protocol"  # Protocol string
        + b"\x00" * 8  # Reserved bytes
        + info_hash  # 20-byte info hash
        + peer_id  # Your 20-byte peer ID
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, peer_port))
        s.send(handshake_message)
        response = s.recv(68)  # Handshake response

        # Wait for the bitfield message (ID 5)
        msg_id, _ = receive_message(s)
        if msg_id != 5:
            raise Exception("Expected bitfield message")

        # Send interested message (ID 2)
        send_message(s, 2)

        # Wait for unchoke message (ID 1)
        msg_id, _ = receive_message(s)
        if msg_id != 1:
            raise Exception("Expected unchoke message")

        # Download the piece by sending block requests
        piece_data = b""
        block_size = 16 * 1024
        for offset in range(0, piece_length, block_size):
            block_length = min(block_size, piece_length - offset)
            payload = (
                struct.pack(">I", piece_index)
                + struct.pack(">I", offset)
                + struct.pack(">I", block_length)
            )
            send_message(s, 6, payload)  # Request message (ID 6)

            # Receive piece message (ID 7)
            msg_id, payload = receive_message(s)
            if msg_id != 7:
                raise Exception("Expected piece message")
            piece_data += payload[
                8:
            ]  # The block data starts at byte 9 (after index and begin)

        # Verify the piece's hash
        piece_hash = hashlib.sha1(piece_data).digest()
        if piece_hash != formatted_pieces[torrent["info"]["pieces"]][piece_index]:
            raise Exception("Piece hash mismatch")

        # Write the piece to disk
        with open(output_path, "wb") as f:
            f.write(piece_data)
        print(f"Piece {piece_index} downloaded and saved to {output_path}")


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
    elif command == "peers":
        file_name = sys.argv[2]

        try:
            with open(file_name, "rb") as torrent_file:
                bencoded_content = torrent_file.read()
                decoder = bencodeDecoder(bencoded_content)
                torrent = decoder.decode()
                info_hash = calculate_info_hash(torrent["info"])
                peer_id = generate_peer_id()
                discover_peers(torrent, info_hash, peer_id)
        except FileNotFoundError:
            print(f"Error: File '{file_name}' not found.")
        except KeyError as e:
            print(f"Error: Missing expected field in torrent file: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    elif command == "download_piece":
        output_path = sys.argv[3]
        file_name = sys.argv[4]
        piece_index = int(sys.argv[5])

        try:
            with open(file_name, "rb") as torrent_file:
                bencoded_content = torrent_file.read()
                decoder = bencodeDecoder(bencoded_content)
                torrent = decoder.decode()
                info_hash = calculate_info_hash(torrent["info"])
                piece_length = torrent["info"]["piece length"]
                peer_ip = "127.0.0.1"  # Replace with actual peer IP
                peer_port = 6881  # Replace with actual peer port
                download_piece(
                    peer_ip,
                    peer_port,
                    info_hash,
                    piece_index,
                    piece_length,
                    output_path,
                )
        except FileNotFoundError:
            print(f"Error: File '{file_name}' not found.")
        except KeyError as e:
            print(f"Error: Missing expected field in torrent file: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

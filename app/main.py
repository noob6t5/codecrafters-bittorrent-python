import json
import os
import sys
import hashlib
import requests
import random, math
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


def download_piece_from_peer(
    peer_ip: str,
    peer_port: int,
    info_hash: bytes,
    peer_id: bytes,
    piece_index: int,
    piece_length: int,
    piece_hash: str,
    output_file: str,
):
    block_size = 2**14  # 16 KB
    blocks = []
    offset = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect and perform handshake
        s.connect((peer_ip, peer_port))
        peer_id = perform_handshake(peer_ip, peer_port, info_hash)

        # Send 'interested' message (length 1 + message id 2)
        s.send(struct.pack(">Ib", 1, 2))

        # Read unchoke message
        response = s.recv(5)
        if response[3] != 1:  # Check if it's an unchoke message (ID=1)
            raise Exception("Peer didn't unchoke")
        while offset < piece_length:
            block_len = min(block_size, piece_length - offset)
            request_msg = struct.pack(">IbIII", 13, 6, piece_index, offset, block_len)
            s.send(request_msg)
            response = s.recv(
                9 + block_len
            )  # message length (4) + message id (1) + index (4) + begin (4) + block
            blocks.append(response[13:])  # The block starts after the 13th byte
            offset += block_len
        piece_data = b"".join(blocks)

        # Verify the piece hash
        downloaded_piece_hash = hashlib.sha1(piece_data).hexdigest()
        if downloaded_piece_hash != piece_hash:
            raise Exception("Piece hash does not match. Data is corrupted.")

        # Write the piece to disk
        with open(output_file, "wb") as f:
            f.write(piece_data)
        print(f"Downloaded piece {piece_index} successfully and saved to {output_file}")


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
                peer_id = generate_peer_id()  
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
        if len(sys.argv) != 6 or sys.argv[3] != "-o":
            raise ValueError("Invalid command format. Expected: download_piece <torrent_file> -o <output_file> <piece_index>")

    file_name = sys.argv[2]
    output_file = sys.argv[4]
    piece_index = int(sys.argv[5])
    
    try:
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()
            decoder = bencodeDecoder(bencoded_content)
            torrent = decoder.decode()

            info_hash = calculate_info_hash(torrent["info"])
            peer_id = generate_peer_id()
            piece_length = torrent["info"]["piece length"]
            piece_hashes = formatted_pieces(torrent["info"]["pieces"])

            # Discover peers and use the first peer for downloading
            tracker_peers = discover_peers(torrent, info_hash, peer_id)
            if not tracker_peers:
                raise Exception("No peers found.")
            first_peer = tracker_peers[0]
            peer_ip, peer_port = first_peer.split(":")
            peer_port = int(peer_port)

            # Download the requested piece
            download_piece_from_peer(peer_ip, peer_port, info_hash, peer_id, piece_index, piece_length, piece_hashes[piece_index], output_file)
    except FileNotFoundError:
        print(f"Error: File '{file_name}' not found.")
    except KeyError as e:
        print(f"Error: Missing expected field in torrent file: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

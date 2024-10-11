import json
import sys
import hashlib
import requests
import os
import socket
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
            return str_value  # Return the raw bytes if decoding fails

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


def calculate_info_hash(info_dict):
    # Re-bencode the info dictionary using the bencode function
    bencoded_info = bencode(info_dict)
    return hashlib.sha1(bencoded_info).digest()  # Return the binary digest


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


def formatted_pieces(pieces: bytes) -> List[str]:
    return [pieces[i : i + 20].hex() for i in range(0, len(pieces), 20)]


def generate_random_peer_id() -> bytes:
    client_name = b"MyClient"  # You can replace this with any string of your choice
    random_bytes = os.urandom(8) 
    return b"-" + client_name + random_bytes


def create_handshake(infohash: bytes, peer_id: bytes) -> bytes:
    protocol = b"BitTorrent protocol"
    reserved = b"\x00" * 8
    handshake_message = (
        bytes([len(protocol)]) + protocol + reserved + infohash + peer_id
    )
    return handshake_message


def handshake(peer_ip: str, peer_port: int, infohash: bytes) -> str:
    peer_id = generate_random_peer_id()
    handshake_message = create_handshake(infohash, peer_id)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((peer_ip, peer_port))
        sock.send(handshake_message)
        response = sock.recv(68)  # Handshake response should be 68 bytes long
        received_peer_id = response[-20:]

        return received_peer_id.hex()


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

            # Calculate the info hash
            info_hash = calculate_info_hash(torrent["info"])
            print("Info Hash:", info_hash.hex())  # Print the hex representation
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
            url = torrent["announce"]
            info_hash = calculate_info_hash(torrent["info"])
            query_params = {
                "info_hash": info_hash,
                "peer_id": generate_random_peer_id(),  # Use random peer ID for peers command
                "port": 6881,
                "uploaded": 0,
                "downloaded": 0,
                "left": torrent["info"]["length"],
                "compact": 1,
            }

            # Make GET request to the tracker
            response = requests.get(url, params=query_params)
            response_data = bencodeDecoder(response.content).decode()["peers"]

            if "peers" in response_data:
                peers = response_data["peers"]
                for i in range(0, len(peers), 6):
                    peer = peers[i : i + 6]
                    ip_address = f"{peer[0]}.{peer[1]}.{peer[2]}.{peer[3]}"
                    port = int.from_bytes(peer[4:], byteorder="big")
                    print(f"{ip_address}:{port}")
            else:
                print("Error: 'peers' field is missing in the response.")

        except FileNotFoundError:
            print(f"Error: File '{file_name}' not found.")
        except KeyError as e:
            print(f"Error: Missing expected field in torrent file: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    elif command == "handshake":
        file_name = sys.argv[2]
        peer_address = sys.argv[3]
        try:
            with open(file_name, "rb") as torrent_file:
                bencoded_content = torrent_file.read()

            decoder = bencodeDecoder(bencoded_content)
            torrent = decoder.decode()
            info_hash = calculate_info_hash(torrent["info"])
            peer_ip, peer_port = peer_address.split(":")
            peer_port = int(peer_port)

            peer_id = handshake(peer_ip, peer_port, info_hash)
            print(f"Peer ID: {peer_id}")

        except FileNotFoundError:
            print(f"Error: File '{file_name}' not found.")
        except KeyError as e:
            print(f"Error: Missing expected field in torrent file: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

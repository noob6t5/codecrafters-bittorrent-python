import json
import sys


def decode_bencode(bencoded_value):
    if bencoded_value[0] == ord("i"):  # Check if the value is a bencoded integer
        end_index = bencoded_value.find(b"e")
        if end_index == -1:
            raise ValueError("Invalid encoded integer")
        return int(bencoded_value[1:end_index])  
    elif chr(bencoded_value[0]).isdigit():  
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        return bencoded_value[first_colon_index + 1 :]
    else:
        raise NotImplementedError(
            "Only strings and integers are supported at the moment"
        )


def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()

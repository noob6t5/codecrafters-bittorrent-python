import json
import sys


def decode_bencode(bencoded_value, index=0):
    if bencoded_value[index] == ord("i"):  # Check for an integer
        end_index = bencoded_value.find(b"e", index)
        if end_index == -1:
            raise ValueError("Invalid encoded integer")
        return (int(bencoded_value[index + 1 : end_index]),end_index + 1,) 

    elif bencoded_value[index] == ord("l"):  # Check for a list
        result_list = []
        index += 1  
        while index < len(bencoded_value) and bencoded_value[index] != ord("e" ):  
            element, new_index = decode_bencode(
                bencoded_value, index
            )  # Decode the element
            result_list.append(element)  # Append 
            index = new_index  
        if index >= len(bencoded_value) or bencoded_value[index] != ord("e"):
            raise ValueError("Invalid encoded list")   

        return result_list, index + 1  

    elif chr(bencoded_value[index]).isdigit():  
        first_colon_index = bencoded_value.find(b":", index)
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        length = int(bencoded_value[index:first_colon_index])  # Length of the string
        start_index = first_colon_index + 1
        end_index = start_index + length
        if end_index > len(bencoded_value):
            raise ValueError("Invalid string length")
        return (bencoded_value[start_index:end_index], end_index,)  
    else:
        raise NotImplementedError(
            "Error"
        )


def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
            raise TypeError(f"Type not serializable: {type(data)}")
        decoded_value, _ = decode_bencode(bencoded_value)  # Start decoding from index 0
        print(json.dumps(decoded_value, default=bytes_to_str))  
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()

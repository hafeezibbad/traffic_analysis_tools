import json


def print_json(data: dict, indent: int = 2, sort_keys: bool = True):
    print(json.dumps(data, indent=indent, sort_keys=sort_keys))


def write_json_to_file(data: dict, file_path: str, indent: int = 2, sort_keys: bool = True):
    with open(file_path, 'w') as out_file:
        json.dump(data, out_file, indent=indent, sort_keys=sort_keys)
    print('{} written to {}'.format(data, file_path))

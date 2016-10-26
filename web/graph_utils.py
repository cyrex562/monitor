import json
import os
import random
import string

import jsonpickle

cwd = os.getcwd()
path = cwd.replace('web', 'config')
DATA_DIR = path

id_len = 4
id_chars = string.ascii_uppercase + string.digits


def gen_id():
    generated_id = ''
    for i in range(0, id_len, 1):
        generated_id += random.choice(id_chars)
    return generated_id


def get_elements_as_dict():
    elements_file = open(os.path.join(DATA_DIR, "elements.json"), "r")
    elements_buf = elements_file.read()
    elements_file.close()
    elements_dict = jsonpickle.decode(elements_buf)
    return elements_dict


def update_elements_with_dict(elements):
    # elements_json = jsonpickle.encode(elements)
    elements_json = json.dumps(elements, indent=1)
    elements_file = open(os.path.join(DATA_DIR, "elements.json"), "w+")

    # item = pprint.pformat(elements_json, indent=1, width=80)
    elements_file.write(elements_json)
    elements_file.close()

# END OF FILE #

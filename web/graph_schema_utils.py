import argparse
import graph_utils

node_ids = {}


def standardize_element_ids(graph_dict):
    # iterate over elements
    for element in graph_dict["elements"]:
        # record all old node_ids
        if element["group"] == "nodes":
            old_node_id = element["data"]["id"]
            new_node_id = graph_utils.gen_id()
            print("old_node_id: {0}, new_node_id: {1}".format(old_node_id,
                                                              new_node_id))
            # node_ids.append(dict(old_id=old_node_id, new_id=new_node_id))
            node_ids[old_node_id] = new_node_id

    for element in graph_dict["elements"]:
        if element["group"] == "nodes":
            # replace node id with new node id
            element["data"]["id"] = node_ids[element["data"]["id"]]

        elif element["group"] == "edges":
            element["data"]["id"] = graph_utils.gen_id()
            element["data"]["source"] = node_ids[element["data"]["source"]]
            element["data"]["target"] = node_ids[element["data"]["target"]]

    return graph_dict


def move_name_and_desc(graph_dict):
    new_elements = []
    for element in graph_dict["elements"]:
        new_ele = dict(
            group=element["group"],
            data=dict(
                id=element["data"]["id"],
                name=element["name"],
                description=element["description"]))
        if element["group"] == "edges":
            new_ele["data"]["source_data"] = {"name": "", "description": ""}
            new_ele["data"]["sink_data"] = {"name": "", "description": ""}
            new_ele["data"]["source_data"]["name"] = element["source"]["name"]
            new_ele["data"]["source_data"]["description"] = \
                element["source"]["description"]
            new_ele["data"]["sink_data"]["name"] = element["sink"]["name"]
            new_ele["data"]["sink_data"]["description"] = \
                element["sink"]["description"]
            new_ele["data"]["source"] = element["data"]["source"]
            new_ele["data"]["target"] = element["data"]["target"]
        new_elements.append(new_ele)
    graph_dict["elements"] = new_elements
    return graph_dict


def add_name_and_desc(graph_dict):
    for element in graph_dict["elements"]:
        # check if the element contains a name field, create one if it does not
        if "name" not in element:
            element["name"] = ""
        # check if the element contains a description field, create on if it
        # does not
        if "description" not in element:
            element["description"] = ""

        # if the element is an edge, than also provide a name for the source
        # and one for the sink
        if element["group"] == "edges":
            # and a description for the source
            if "source" not in element:
                element["source"] = {}

            if "name" not in element["source"]:
                element["source"]["name"] = ""

            if "description" not in element["source"]:
                element["source"]["description"] = ""

            if "sink" not in element:
                element["sink"] = {}

            if "name" not in element["sink"]:
                element["sink"]["name"] = ""

            if "description" not in element["sink"]:
                element["sink"]["description"] = ""

    return graph_dict


def run():
    parser = argparse.ArgumentParser(description="schema upgrade tool")
    parser.add_argument(
        "--fix_ids",
        action='store_true',
        help="ensure every element has an id that's random")
    parser.add_argument(
        "--fix_name_and_desc",
        action="store_true",
        help="ensure every element has a name and description fields"
    )
    parser.add_argument(
        "--move_name_and_desc",
        action="store_true",
        help="move name and description to data group"
    )

    args = parser.parse_args()

    graph_dict = graph_utils.get_elements_as_dict()

    if args.fix_ids is True:
        graph_dict = standardize_element_ids(graph_dict)
    if args.fix_name_and_desc is True:
        graph_dict = add_name_and_desc(graph_dict)
    if args.move_name_and_desc is True:
        graph_dict = move_name_and_desc(graph_dict)

    graph_utils.update_elements_with_dict(graph_dict)


if __name__ == "__main__":
    run()

# END OF FILE #

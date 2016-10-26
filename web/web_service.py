import os

import graph_utils
import jsonpickle
from bottle import route, run, static_file, get, post, request, delete, put

# app = Bottle()

cwd = os.getcwd()
static_path = os.path.join(cwd, 'static')


@route('/')
def default_route():
    return static_file('/main.html', root=static_path)


@route('/js/<filename>')
def js_route(filename):
    return static_file('/js/' + filename, root=static_path)


@route('/css/<filename>')
def css_route(filename):
    return static_file('/css/' + filename, root=static_path)


@route('/img/<filename>')
def img_route(filename):
    return static_file('/img/' + filename, root=static_path)


@route('/fonts/<filename>')
def fnt_route(filename):
    return static_file('/fonts/' + filename, root=static_path)


@route('/data/<filename>')
def data_route(filename):
    return static_file('/data/' + filename, root=static_path)


@get('/api/elements')
def get_elements():
    elements_dict = graph_utils.get_elements_as_dict()
    elements_json = jsonpickle.encode(elements_dict)
    return elements_json


@post('/api/node')
def create_node():
    # node_id = request.json["node_id"]
    curr_elements = jsonpickle.decode(get_elements())
    new_node = dict(
        group="nodes",
        data=dict(
            id=graph_utils.gen_id(),
            name=request.json["name"],
            description=request.json["description"]))
    curr_elements["elements"].append(new_node)
    graph_utils.update_elements_with_dict(curr_elements)
    return jsonpickle.encode(curr_elements)


@put('/api/node')
def update_node():
    node_id = request.json["node_id"]
    node_desc = request.json["description"]
    node_name = request.json["name"]
    curr_elements = jsonpickle.decode(get_elements())
    for ce in curr_elements["elements"]:
        if ce["group"] == "nodes" and ce["data"]["id"] == node_id:
            # update node name
            if ce["data"]["description"] != node_desc.strip():
                ce["data"]["description"] = node_desc.strip()
            # update node desc
            if ce["data"]["name"] != node_name.strip():
                ce["data"]["name"] = node_name.strip()
    graph_utils.update_elements_with_dict(curr_elements)
    return jsonpickle.encode(curr_elements)


@delete('/api/node')
def delete_node():
    curr_elements = jsonpickle.decode(get_elements())
    node_id = request.json["node_id"]
    node_to_remove = None
    edges_to_remove = []
    for ce in curr_elements["elements"]:
        if ce["group"] == "nodes" and ce["data"]["id"] == node_id:
            node_to_remove = ce
        elif ce["group"] == "edges" and \
                (ce["data"]["source"] == node_id or
                         ce["data"]["target"] == node_id):
            edges_to_remove.append(ce)

    if node_to_remove is not None:
        curr_elements["elements"].remove(node_to_remove)

    if len(edges_to_remove) > 0:
        for edge in edges_to_remove:
            curr_elements["elements"].remove(edge)

    graph_utils.update_elements_with_dict(curr_elements)
    return jsonpickle.encode(curr_elements)


@post('/api/edge')
def create_edge():
    curr_elements = jsonpickle.decode(get_elements())
    # edge_id = request.json.get("edge_id", "")
    edge_source = request.json.get("edge_source", "")
    edge_target = request.json.get("edge_target", "")
    edge_name = request.json.get("edge_name", "")
    edge_description = request.json.get("edge_description", "")
    source_name = request.json.get("source_name", "")
    source_description = request.json.get("source_description", "")
    target_name = request.json.get("target_name", "")
    target_description = request.json.get("target_description", "")
    # FIXME: if edge_source or edge_target are not present, then return an error

    source_data = dict(name=source_name, description=source_description)
    target_data = dict(name=target_name, description=target_description)
    new_edge = dict(group="edges",
                    data=dict(id=graph_utils.gen_id(),
                              name=edge_name,
                              description=edge_description,
                              source=edge_source,
                              target=edge_target,
                              source_data=source_data,
                              target_data=target_data))

    curr_elements["elements"].append(new_edge)

    graph_utils.update_elements_with_dict(curr_elements)
    return jsonpickle.encode(curr_elements)


@put('/api/edge')
def update_edge():
    curr_elements = jsonpickle.decode(get_elements())
    edge_id = request.json.get("edge_id", "")
    edge_name = request.json.get("edge_name", "")
    edge_description = request.json.get("edge_description", "")
    edge_source = request.json.get("edge_source", "")
    edge_target = request.json.get("edge_target", "")
    source_name = request.json.get("source_name", "")
    source_description = request.json.get("source_description", "")
    target_name = request.json.get("target_name", "")
    target_description = request.json.get("target_description", "")

    for ce in curr_elements["elements"]:
        if ce["group"] == "edges":
            if ce["data"]["id"] == edge_id:
                ce["data"]["source"] = edge_source
                ce["data"]["target"] = edge_target
                ce["data"]["name"] = edge_name
                ce["data"]["description"] = edge_description
                ce["data"]["source_data"]["name"] = source_name
                ce["data"]["source_data"]["description"] = source_description
                ce["data"]["target_data"]["name"] = target_name
                ce["data"]["target_data"]["description"] = target_description
                break

    graph_utils.update_elements_with_dict(curr_elements)
    return jsonpickle.encode(curr_elements)


@delete('/api/edge')
def delete_edge():
    curr_elements = jsonpickle.decode(get_elements())
    edge_id = request.json["edge_id"]

    edge_to_remove = None
    for ce in curr_elements["elements"]:
        if ce["group"] == "edges" and ce["data"]["id"] == edge_id:
            edge_to_remove = ce

    if edge_to_remove is not None:
        curr_elements["elements"].remove(edge_to_remove)
        graph_utils.update_elements_with_dict(curr_elements)

    return jsonpickle.encode(curr_elements)


run(host='localhost', port=8001, debug=True)

# END OF FILE #

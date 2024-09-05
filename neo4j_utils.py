from py2neo import Node, Relationship


def upload_graph_to_neo4j(
        neo4j_graph_connection,
        visited,
        horizon,
        attackgraph,
        path,
        add_horizon=False
    ):
    """
    Uploads the traversed path and attacker horizon (optional) by the attacker to the Neo4j database.

    Parameters:
    - neo4j_graph_connection: The Neo4j Graph instance.
    - visited
    - horizon
    - attackgraph
    - add_horizon: Flag which if True, adds on the horizon to Neo4j.

    """
    
    nodes = {}
    neo4j_graph_connection.delete_all()
    
    # Build attack steps for Neo4j from all visited nodes.
    nodes = create_neo4j_node(neo4j_graph_connection, visited, nodes)
    if horizon and add_horizon:
        nodes = create_neo4j_node(neo4j_graph_connection, horizon, nodes, is_horizon_node=True)

    # Add edges to the attack graph in Neo4j.
    for node_id in [node.id for node in attackgraph.nodes]:
        if node_id in nodes.keys():
            for link in path[node_id]:
                if link.id in nodes.keys():
                    from_node = nodes[node_id]
                    to_node = nodes[link.id]
                    if (from_node['is_horizon_node'] == False and to_node['is_horizon_node'] == False) or \
                    (from_node['is_horizon_node'] == False and to_node['is_horizon_node'] == True):
                        relationship = Relationship(from_node, "Relationship", to_node)
                        neo4j_graph_connection.create(relationship)


def create_neo4j_node(
        neo4j_graph_connection,
        set_of_nodes,
        neo4j_node_dict,
        is_horizon_node=False
    ):
    for node in set_of_nodes:
        if not node.id in neo4j_node_dict.keys():
            asset_and_id = node.full_name.split(':')
            asset_and_id = asset_and_id[0] + ':' + asset_and_id[1]
            neo4j_node = Node(
                str(asset_and_id),
                str(is_horizon_node),
                is_horizon_node = is_horizon_node,
                name = node.name,
                full_name = node.id,
                type = node.type,
                ttc = str(node.ttc),
                cost = None,
                is_necessary = str(node.is_necessary),
                is_viable = str(node.is_viable),
            )
            neo4j_graph_connection.create(neo4j_node)
            neo4j_node_dict[node.id] = neo4j_node
    return neo4j_node_dict

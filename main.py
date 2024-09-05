import maltoolbox.wrappers
from py2neo import Graph
import maltoolbox.attackgraph.attackgraph
import maltoolbox.ingestors.neo4j
import maltoolbox.language.classes_factory
from maltoolbox.attackgraph.analyzers.apriori import calculate_viability_and_necessity

from maltoolbox.wrappers import create_attack_graph

from attack_simulation import AttackSimulation
import constants
import help_functions


def print_nodes(nodes: list):
    """Print list of visited nodes"""
    print("  Visited:")
    for node in nodes:
        print(f"\t- {node.full_name} (id: {node.id})")


def main():
    # Connect to Neo4j graph database.
    # print("Starting to connect to Neo4j database.")
    # neo4j_graph_connection = Graph(uri=constants.URI, user=constants.USERNAME, password=constants.PASSWORD, name=constants.DBNAME)
    neo4j_graph_connection = None
    # print("Successful connection to Neo4j database.")

    # Generate mal-toolbox AttackGraph.
    attackgraph = create_attack_graph(constants.MAR_ARCHIVE, constants.MODEL_FILE)

    # Select one attacker for the simulation.
    # Note: it is possible to add a custom attacker with the model module and thereafter you can run attackgraph.attach_attackers.
    attacker = attackgraph.attackers[0]

    # Calculate viability and necessity of nodes in attackgraph.
    # Note: earlier all defenses had the setting is_necessary=False.
    calculate_viability_and_necessity(attackgraph)

    # Upload the attack graph and model to Neo4j.
    # print("Starting uploading the model and attackgraph to Neo4j.")
    # maltoolbox.ingestors.neo4j.ingest_attack_graph(attackgraph, constants.URI, constants.USERNAME, constants.PASSWORD, constants.DBNAME, delete=True)
    # maltoolbox.ingestors.neo4j.ingest_model(attackgraph.model, constants.URI, constants.USERNAME, constants.PASSWORD, constants.DBNAME, delete=False)
    # print("The model and attackgraph is uploaded to Neo4j.")

    # Load costs
    costs = {}
    if constants.COST_FILE:
        costs = help_functions.load_costs_from_file(constants.COST_FILE)
        # Convert from {full_name: cost} to {id: cost}
        costs = {
            attackgraph.get_node_by_full_name(name).id: value
            for name, value in costs.items()
        }

    # Ask user to select attacker
    possible_attackers = [f"{a.name} ({a.id})" for a in attackgraph.attackers]
    attacker_id = input(
        f"Enter the attacker id to use [{', '.join(possible_attackers)}]: ")
    if attacker := attackgraph.get_attacker_by_id(int(attacker_id)):
        # Create AttackSimulation.
        attack_simulation = AttackSimulation(attackgraph, attacker, costs)
    else:
        raise LookupError("Attacker with id not found")

    # Display algorithm options.
    attack_options = list(constants.ATTACK_OPTIONS.keys())
    print(
        f"{constants.PINK}Choose any of the options below. "
        f"If you want to exit, press any key.{constants.STANDARD}"
    )
    help_functions.print_dictionary(constants.ATTACK_OPTIONS)
    user_input = input(f"Which simulation? {attack_options}:")

    if user_input == attack_options[0]:
        # Traverse attack graph step by step.
        print(f"{constants.PINK}{constants.ATTACK_OPTIONS[user_input]}{constants.STANDARD}")
        attack_simulation.step_by_step_attack_simulation(neo4j_graph_connection)
        # attack_simulation.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=True)

    elif user_input == attack_options[1]:
        # Traverse attack graph with modified Dijkstra's algorithm - to get the shortest path.
        print(f"{constants.PINK}{constants.ATTACK_OPTIONS[user_input]}{constants.STANDARD}")
        target_node_fn = input("Enter the target node full_name: ")
        if target_node := attackgraph.get_node_by_full_name(target_node_fn):
            attack_simulation.set_target_node(target_node)
            min_costs = attack_simulation.dijkstra()
            print("The cost for the attacker traversing the path:", min_costs[target_node.id])
            # attack_simulation.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=False)
        else:
            raise LookupError("Could not find target node")

    elif user_input == attack_options[2]:
        # Traverse attack graph with random algorithm - to get a random path.
        # It is optional to enter a target and attacker cost budget.
        print(f"{constants.PINK}{constants.ATTACK_OPTIONS[user_input]}{constants.STANDARD}")

        target_node_fn = input("Enter the target node full name (or press enter): ")
        if target_node := attackgraph.get_node_by_full_name(target_node_fn):
            attack_simulation.set_target_node(target_node)
        else:
            raise LookupError("Could not find target node")

        attacker_cost_budget = input("Enter the attacker cost budget as integer (or press enter): ")
        if attacker_cost_budget:
            attack_simulation.set_attacker_cost_budget(int(attacker_cost_budget))

        cost, visited = attack_simulation.random_path()
        if attack_simulation.target_node and attack_simulation.target_node in attack_simulation.visited:
            print("The target node was reached.")
        else:
            print("The target node was not reached.")
        print("The cost for the attacker traversing the path:", cost)
        print_nodes(visited)
        # attack_simulation.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=False)

    elif user_input == attack_options[3]:
        # Traverse attack graph with breadth first search to retrieve
        # the subgraph within the attacker cost budget.
        print(f"{constants.PINK}{constants.ATTACK_OPTIONS[user_input]}{constants.STANDARD}")
        attacker_cost_budget = input("Enter the attacker cost budget as integer: ")
        if attacker_cost_budget != '':
            attack_simulation.set_attacker_cost_budget(int(attacker_cost_budget))
            cost, visited = attack_simulation.bfs()
            print("The cost for the attacker for traversing the path", cost)
            print_nodes(visited)
            # attack_simulation.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=False)

if __name__=='__main__':
    main()

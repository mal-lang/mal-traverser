import maltoolbox.wrappers
from py2neo import Graph
import maltoolbox.attackgraph.attackgraph
import maltoolbox.ingestors.neo4j
import maltoolbox.language.classes_factory
import maltoolbox.attackgraph.analyzers.apriori

from maltoolbox.attackgraph import AttackGraphNode
from maltoolbox.wrappers import create_attack_graph

from attack_simulation import AttackSimulation
import constants
import help_functions


def main():
    # Connect to Neo4j graph database.
    print("Starting to connect to Neo4j database.")
    neo4j_graph_connection = Graph(uri=constants.URI, user=constants.USERNAME, password=constants.PASSWORD, name=constants.DBNAME)
    print("Successful connection to Neo4j database.")

    # Generate mal-toolbox AttackGraph.
    attackgraph = create_attack_graph(constants.MAR_ARCHIVE, constants.MODEL_FILE)

    # Select one attacker for the simulation.
    # Note: it is possible to add a custom attacker with the model module and thereafter you can run attackgraph.attach_attackers.
    attacker = attackgraph.attackers[0]

    # Create a firstStep node
    attacker_node = AttackGraphNode(
            type = 'or',
            asset = None,
            name = 'firstSteps',
            ttc = {},
            children = attacker.entry_points,
            parents = [],
            compromised_by = []
    )
    attackgraph.add_node(attacker_node)

    attacker_entry_point = attacker_node.id
    print("Attacker attack step id:", attacker_entry_point)

    # Calculate viability and necessity of nodes in attackgraph.
    # Note: earlier all defenses had the setting is_necessary=False.
    maltoolbox.attackgraph.analyzers.apriori.calculate_viability_and_necessity(attackgraph)

    # Upload the attack graph and model to Neo4j.
    print("Starting uploading the model and attackgraph to Neo4j.")
    maltoolbox.ingestors.neo4j.ingest_attack_graph(attackgraph, constants.URI, constants.USERNAME, constants.PASSWORD, constants.DBNAME, delete=True)
    maltoolbox.ingestors.neo4j.ingest_model(attackgraph.model, constants.URI, constants.USERNAME, constants.PASSWORD, constants.DBNAME, delete=False)
    print("The model and attackgraph is uploaded to Neo4j.")

    # Create AttackSimulation.
    attack_simulation = AttackSimulation(attackgraph, attacker, use_ttc=False) 

    # Display algorithm options.
    attack_options = list(constants.ATTACK_OPTIONS.keys())
    print(f"{constants.PINK}Choose any of the options below. If you want to exit, press any key.{constants.STANDARD}")
    help_functions.print_dictionary(constants.ATTACK_OPTIONS)
    user_input = input(f"Which simulation? {attack_options}:")
    
    if user_input == attack_options[0]:
        # Traverse attack graph step by step.
        print(f"{constants.PINK}{constants.ATTACK_OPTIONS[user_input]}{constants.STANDARD}")
        attack_simulation.step_by_step_attack_simulation(neo4j_graph_connection)
        attack_simulation.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=True)

    elif user_input == attack_options[1]:
        # Traverse attack graph with modified Dijkstra's algorithm - to get the shortest path.
        print(f"{constants.PINK}{constants.ATTACK_OPTIONS[user_input]}{constants.STANDARD}")
        target_node_id = input("Enter the target node id: ")
        if target_node_id in attack_simulation.attackgraph_dictionary.keys():
            attack_simulation.set_target_node(target_node_id)
            cost = attack_simulation.dijkstra()
            print("The cost for the attacker for traversing the path", cost)
            attack_simulation.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=False)

    elif user_input == attack_options[2]:
        # Traverse attack graph with random algorithm - to get a random path.
        # It is optional to enter a target and attacker cost budget.
        print(f"{constants.PINK}{constants.ATTACK_OPTIONS[user_input]}{constants.STANDARD}")
        target_node_id = input("Enter the target node id (or press enter): ")
        if target_node_id in attack_simulation.attackgraph_dictionary.keys():
            attack_simulation.set_target_node(target_node_id)
        attacker_cost_budget = input("Enter the attacker cost budget as integer (or press enter): ")
        if attacker_cost_budget != '':
            attack_simulation.set_attacker_cost_budget(int(attacker_cost_budget))
        cost = attack_simulation.random_path()
        if attack_simulation.target_node != None and attack_simulation.target_node in attack_simulation.visited:
            print("The target was found.")
        print("The cost for the attacker for traversing the path", cost)
        attack_simulation.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=False)

    elif user_input == attack_options[3]:
        # Traverse attack graph with breadth first search to retrieve the subgraph within the attacker
        # cost budget.
        print(f"{constants.PINK}{constants.ATTACK_OPTIONS[user_input]}{constants.STANDARD}")
        attacker_cost_budget = input("Enter the attacker cost budget as integer: ")
        if attacker_cost_budget != '':
            attack_simulation.set_attacker_cost_budget(int(attacker_cost_budget))
            cost = attack_simulation.bfs()
            print("The cost for the attacker for traversing the path", cost)
            attack_simulation.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=False)

if __name__=='__main__':
    main()

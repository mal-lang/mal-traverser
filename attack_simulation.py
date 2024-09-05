from dataclasses import dataclass, field

from maltoolbox.attackgraph.query import (
    get_attack_surface,
    is_node_traversable_by_attacker
)
import maltoolbox
import maltoolbox.attackgraph.attackgraph

from maltoolbox.attackgraph import Attacker, AttackGraph, AttackGraphNode
from collections import deque
import heapq
import random

import help_functions
import constants
from neo4j_utils import upload_graph_to_neo4j
from traversers import (
    multi_source_dijkstra_with_costs,
    cheapest_compromises_to_reach,
    random_path,
    bfs
)

from typing import Optional

class AttackSimulation:

    def __init__(
            self,
            attackgraph: AttackGraph,
            attacker: Attacker,
            costs: Optional[dict[int, int]] = None
        ):
        """
        Initialize the AttackSimulation instance.

        Parameters:
        - attackgraph_instance: An instance of the AttackGraph class.
        - attacker: An instance of the Attacker class.
        - use_ttc: Boolean indicating whether Time-To-Compromise (TTC) is used. Default is True.
        - costs: a dictionary with costs to reach each node from a neighbor
        """

        self.attackgraph = attackgraph
        self.attacker = attacker
        self.attacker_cost_budget: Optional[int] = None

        self.horizon = []
        self.visited = []
        self.path = {node.id: [] for node in attackgraph.nodes}
        self.costs = costs or self.get_cost_from_ttc()

        self.target_node: AttackGraphNode = None

    def set_target_node(self, target_node_id: AttackGraphNode):
        """
        Set the target node for traversers.

        Parameters:
        - target_node: The target node.
        """
        self.target_node = target_node_id

    def set_attacker_cost_budget(self, attacker_cost_budget: int):
        """
        Set the attacker's cost budget for traversers.

        Parameters:
        - attacker_cost_budget: The budget representing the cost budget of the attacker.
        """
        self.attacker_cost_budget = attacker_cost_budget

    def get_cost_from_ttc(self) -> dict[int, int]:
        """Create an edge cost dict from ttc values"""
        cost_dictionary = {}
        for attackgraph_node in self.attackgraph.nodes:
            ttc = attackgraph_node.ttc
            if not ttc:
                cost_dictionary[attackgraph_node.id] = 0
            else:
                cost_dictionary[attackgraph_node.id] \
                    = help_functions.cost_from_ttc(ttc, 100)
        return cost_dictionary

    def print_attack_surface(self):
        """
        Prints the horizon attack steps and the type in custom format.
        """
        attack_surface_dict = self.build_attack_surface_dict()
        print(f"{constants.RED}Attacker Horizon{constants.STANDARD}")
        help_functions.print_dictionary(attack_surface_dict)

    def build_attack_surface_dict(self) -> dict[str, AttackGraphNode]:
        """
        Build a dictionary with an integer as keys and Node ID:s as values.
        """
        attack_surface_dict = {}
        for i, node in enumerate(self.horizon):
            attack_surface_dict[i+1] = [
                node.id,
                node.full_name + f' ({node.type})'
            ]
        return attack_surface_dict

    def step_by_step_attack_simulation(self, neo4j_graph_connection):
        """
        Traverse the attack graph step by step.
        
        Parameters:
        - neo4j_graph_connection: The Neo4j Graph instance.
        """

        self.horizon = get_attack_surface(self.attacker)
        self.visited = self.attacker.reached_attack_steps

        # Add all children nodes to the path attribute.
        for node in self.attackgraph.nodes:
            self.path[node.id] = node.children.copy()

        # Upload attacker path and horizon.
        # upload_graph_to_neo4j(
        #     neo4j_graph_connection,
        #     self.visited,
        #     self.horizon,
        #     self.attackgraph,
        #     self.path,
        #     add_horizon=True
        # )

        # Begin step by step attack simulation.
        while True:
            print(f"{constants.RED}options{constants.STANDARD}")
            help_functions.print_dictionary(constants.STEP_BY_STEP_ATTACK_COMMANDS)
            command = input("Choose: ")

            # View current attacker horizon.
            if command == '1':
                self.print_attack_surface()

            # Action.
            elif command == '2':
                # Choose next node to visit.
                node_options = self.build_attack_surface_dict()
                self.print_attack_surface()
                option = input("Choose a node (id) to attack: ")
                attacked_node_id = node_options[int(option)][0] # Select the node id at index 0.
                attacked_node = self.attackgraph.get_node_by_id(attacked_node_id)

                # Update horizon if the node can be visited.
                if attacked_node in self.horizon:
                    # Update the path.
                    self.attacker.compromise(attacked_node)
                    self.visited = self.attacker.reached_attack_steps
                    self.horizon = get_attack_surface(self.attacker)
                    self.horizon = [node for node in self.horizon \
                        if self.attacker not in node.compromised_by]

                    # Upload attacker path and horizon.
                    # upload_graph_to_neo4j(
                    #     neo4j_graph_connection,
                    #     self.visited,
                    #     self.horizon,
                    #     self.attackgraph,
                    #     self.path,
                    #     add_horizon=True
                    # )
                    print("Attack step was compromised.")
                else:
                    print("The node does not exist in the attack surface")
                # Print horizon nodes.
                self.print_attack_surface()

            elif command == '3':
                # Return.
                return

    def dijkstra(self):
        """
        Find the shortest path between two nodes using Dijkstra's algorithm with added 
        conditions for processing 'and' nodes.
        Note: mal-toolbox attack surface is not used in this function!
        
        Returns:
        - cost: Total cost of the path.
        """
        return multi_source_dijkstra_with_costs(
            self.attackgraph,
            self.attacker.reached_attack_steps,
            self.costs
        )
    
    def random_path(self):
        """
        Generate a random attack path in the attack graph, considering attacker cost budget and/or target node.

        This method explores a random path in the attack graph from the start node.
        It uses a random selection strategy among the attack surface nodes, considering the attacker's cost budget
        and searching for a specific target node if provided.

        Returns:
        - cost: The total cost of the random path.
        """
        return random_path(
            self.attackgraph,
            self.attacker.reached_attack_steps,
            self.costs,
            self.target_node,
            self.attacker_cost_budget
        )

    def bfs(self):
        """
        Perform Breadth-First Search (BFS) on the attack graph from the start node.

        This method explores the attack graph starting from the specified start node,
        considering a cost budget for the attacker. It calculates the total cost of the
        paths within the budget and returns the final cost. Note that this method does not 
        consider all attack graph logic.

        Returns:
        - cost: The total cost of the paths explored within the attacker's cost budget.
        """
        return bfs(
            self.attackgraph,
            self.attacker.reached_attack_steps,
            self.costs,
            self.attacker_cost_budget
        )

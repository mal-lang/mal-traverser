import maltoolbox.attackgraph.query
import maltoolbox
import maltoolbox.attackgraph.attackgraph
from maltoolbox.attackgraph import Attacker, AttackGraph
from py2neo import Node, Relationship
from collections import deque
import heapq
import random

import help_functions
import constants

class AttackSimulation:
    
    def __init__(self, attackgraph_instance: AttackGraph, attacker: Attacker, use_ttc=True):
        """
        Initialize the AttackSimulation instance.

        Parameters:
        - attackgraph_instance: An instance of the AttackGraph class.
        - attacker: An instance of the Attacker class.
        - use_ttc: Boolean indicating whether Time-To-Compromise (TTC) is used. Default is True.
        """
        self.attackgraph_instance = attackgraph_instance
        self.attackgraph_dictionary = {node.id: node for node in attackgraph_instance.nodes}  # Create a dictionary for quick access to nodes by id
        self.attacker = attacker
        self.start_node = attacker.node.id
        self.target_node = None
        self.attacker_cost_budget = None
        self.use_ttc = use_ttc
        self.horizon = []
        self.visited = []
        self.path = {node.id: [] for node in attackgraph_instance.nodes}
        self.cost_dictionary = self.get_costs()

    def set_target_node(self, target_node_id):
        """
        Set the target node for the simulation.

        Parameters:
        - target_node: The ID of the target node.
        """
        self.target_node = target_node_id

    def set_start_node(self, start_node_id):
        """
        Set the start node for the simulation.

        Parameters:
        - start_node: The ID of the target node.
        """
        self.start_node = start_node_id

    def set_attacker_cost_budget(self, attacker_cost_budget):
        """
        Set the attacker's cost budget for the simulation.

        Parameters:
        - attacker_cost_budget: The budget representing the cost budget of the attacker.
        """
        self.attacker_cost_budget = attacker_cost_budget

    def print_attack_surface(self):
        """
        Prints the horizon attack steps and the type in custom format.
        """
        attack_surface_dict = self.build_attack_surface_dict()
        print(f"{constants.RED}Attacker Horizon{constants.STANDARD}")
        help_functions.print_dictionary(attack_surface_dict)

    def build_attack_surface_dict(self):
        """
        Build a dictionary with an integer as keys and Node ID:s as values.
        
        Return:
        - dict: A dictionary on the form {ID (string): node (AttackGraphNode)}.
        """
        dict = {}
        for i, node in enumerate(self.horizon):
            dict[i+1] = [node.id, node.type, str(maltoolbox.attackgraph.query.is_node_traversable_by_attacker(node, self.attacker))]
        return dict

    def step_by_step_attack_simulation(self, neo4j_graph_connection):
        """
        Traverse the attack graph step by step. 
        
        Parameters:
        - neo4j_graph_connection: The Neo4j Graph instance.
        """
        self.horizon = maltoolbox.attackgraph.query.get_attack_surface(self.attacker)
        self.visited = self.attacker.reached_attack_steps

        # Add all children nodes to the path attribute.     
        for node in self.attackgraph_instance.nodes:
            self.path[node.id] = node.children.copy()

        # Upload attacker path and horizon.
        self.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=True)
            
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
                attacked_node = self.attackgraph_dictionary[attacked_node_id]

                # Update horizon if the node can be visited.
                if attacked_node in self.horizon:
                    # Update the path.
                    self.attacker.compromise(attacked_node)
                    self.visited = self.attacker.reached_attack_steps
                    self.horizon = maltoolbox.attackgraph.query.get_attack_surface(self.attacker)
                    self.horizon = [node for node in self.horizon \
                        if self.attacker not in node.compromised_by]
                   
                    # Upload attacker path and horizon.
                    self.upload_graph_to_neo4j(neo4j_graph_connection, add_horizon=True)
                    print("Attack step was compromised.")
                else:
                    print("The node does not exist in the attack surface")
                # Print horizon nodes.
                self.print_attack_surface()
            elif command == '3':
                # Return.
                return
    
    def create_neo4j_node(self, neo4j_graph_connection, set_of_nodes, neo4j_node_dict, is_horizon_node=False):
        for node in set_of_nodes:
            if not node.id in neo4j_node_dict.keys():
                asset_and_id = node.id.split(':')
                asset_and_id = asset_and_id[0] + ':' + asset_and_id[1]
                neo4j_node = Node(
                    str(asset_and_id),
                    str(is_horizon_node),
                    is_horizon_node = is_horizon_node,
                    name = node.name,
                    full_name = node.id,
                    type = node.type,
                    ttc = str(node.ttc),
                    cost = str(self.cost_dictionary[node.id]) if node.name != "firstSteps" else None,
                    is_necessary = str(node.is_necessary),
                    is_viable = str(node.is_viable),
                )
                neo4j_graph_connection.create(neo4j_node)
                neo4j_node_dict[node.id] = neo4j_node
        return neo4j_node_dict
        
    def upload_graph_to_neo4j(self, neo4j_graph_connection, add_horizon=False):
        """
        Uploads the traversed path and attacker horizon (optional) by the attacker to the Neo4j database.

        Parameters:
        - neo4j_graph_connection: The Neo4j Graph instance.
        - add_horizon: Flag which if True, adds on the horizon to Neo4j.

        Notes:
        - The function assumes the existence of the following variables:
            - self.visited: A list of visited nodes.
            - self.horizon: A list of horizon nodes.
            - self.attackgraph_dictionary: A dictionary representing the attack graph.
            - self.path: A dictionary containing the path.
        """
        
        nodes = {}
        neo4j_graph_connection.delete_all()
       
       # Build attack steps for Neo4j from all visited nodes.
        nodes = self.create_neo4j_node(neo4j_graph_connection, self.visited, nodes)
        if self.horizon and add_horizon:
            nodes = self.create_neo4j_node(neo4j_graph_connection, self.horizon, nodes, is_horizon_node=True)

        # Add edges to the attack graph in Neo4j.
        for id in self.attackgraph_dictionary.keys():
            if id in nodes.keys():
                for link in self.path[id]:
                    if link.id in nodes.keys():
                        from_node = nodes[id]
                        to_node = nodes[link.id]
                        if (from_node['is_horizon_node'] == False and to_node['is_horizon_node'] == False) or \
                        (from_node['is_horizon_node'] == False and to_node['is_horizon_node'] == True):
                            relationship = Relationship(from_node, "Relationship", to_node)
                            neo4j_graph_connection.create(relationship)
    
    def dijkstra(self):
        """
        Find the shortest path between two nodes using Dijkstra's algorithm with added 
        conditions for processing 'and' nodes.
        Note: mal-toolbox attack surface is not used in this function!
        
        Returns:
        - cost: Total cost of the path.
        """
        node_ids = list(self.attackgraph_dictionary.keys())
        open_set = []
        heapq.heappush(open_set, (0, self.start_node))
        came_from = {key: [] for key in node_ids}

        # The g_score is a map with large values.
        g_score = dict.fromkeys(node_ids, 10000)
        g_score[self.start_node] = 0

        # Estimated score between each node and target.
        h_score = dict.fromkeys(node_ids, 0)
    
        # For node n, f_score[n] = g_score[n] + h_score(n). f_score[n] represents our current best guess as to
        # how cheap a path could be from start to finish if it goes through n.
        f_score = dict.fromkeys(node_ids, 0)
        f_score[self.start_node] = h_score[self.start_node]
        
        costs = self.cost_dictionary
        costs_copy = costs.copy()
        current_node = self.start_node
        while len(open_set) > 0:
            # The current_node is the node in open_set having the lowest f_score value.
            _, current_node = heapq.heappop(open_set)

            # Stop when target node is found.
            if current_node == self.target_node:
                self.cost_dictionary = costs_copy
                return self.reconstruct_path(came_from, current_node, costs_copy)[0]

            # Iterate over the attack surface nodes.
            current_neighbors = self.attackgraph_dictionary[current_node].children
            for neighbor in current_neighbors:  
                tentative_g_score = g_score[current_node] + costs[neighbor.id]

                # Try the neighbor node with a lower g_score than the previous node.
                if tentative_g_score < g_score[neighbor.id]:

                    # Add the node to the path.
                    if maltoolbox.attackgraph.query.is_node_traversable_by_attacker(neighbor, self.attacker):
                        came_from[neighbor.id].append(current_node)
                        g_score[neighbor.id] = tentative_g_score
                        f_score[neighbor.id] = tentative_g_score + h_score[neighbor.id] # TODO calculate the h_score for all nodes
                        self.attacker.compromise(neighbor)
                        if neighbor.id not in open_set:
                            heapq.heappush(open_set, (f_score[neighbor.id], neighbor.id))

                    # If 'and' node was not added to the path,
                    # update the node cost and keep track of the path.
                    elif neighbor.type == 'and':
                        costs[neighbor.id] = tentative_g_score
                        came_from[neighbor.id].append(current_node)

                # If a necessary 'and' node was not added to the path and g_scores are equal,
                # update the node cost and keep track of the path.
                elif neighbor.type == 'and' and self.attackgraph_dictionary[current_node].is_necessary == True:
                    costs[neighbor.id] = tentative_g_score
                    came_from[neighbor.id].append(current_node)
        return 0

    def reconstruct_path(self, came_from, current, costs):
        """
        Reconstructs the backwards attack path from the start node to the given node with recursion.

        This method is used in the context of a Djikstra's algorithm to reconstruct
        the optimal path from the target node to the start node, considering a set
        of costs associated with each node in the path.

        Parameters:
        - came_from: A dictionary mapping nodes to their predecessors in the optimal path.
        - current: The node for which the path needs to be reconstructed.
        - costs: A dictionary containing the costs associated with each node.

        Returns:
        - cost: The total cost of the reconstructed path.
        - old_current: The last node in the reconstructed path.
        """
        cost = 0
        visited_set = set()
        if current != self.start_node:
            # Reconstruct the path backwards from current until the start node is reached.
            while current in came_from.keys() and current != self.start_node:
                old_current = current
                # Get all parent nodes to current in the path.
                current = came_from[current]
                # Condition for 'and' nodes.       
                if len(current) > 1:
                    for node in current:
                        if self.attackgraph_dictionary[node].is_necessary == True:
                            path_cost, _= self.reconstruct_path(came_from, node, costs)
                            cost += path_cost + costs[old_current]
                            self.path[node].append(self.attackgraph_dictionary[old_current])
                            visited_set.add(old_current)
                            self.visited.append(self.attackgraph_dictionary[old_current])
                    break
                # Condition for 'or' nodes.
                else:
                    current = current[0]
                    if old_current not in visited_set:
                        visited_set.add(old_current)
                        self.visited.append(self.attackgraph_dictionary[old_current])
                        if self.attackgraph_dictionary[old_current] not in self.path[current]:
                            cost += costs[old_current]
                    if self.attackgraph_dictionary[old_current] not in self.path[current]:
                        self.path[current].append(self.attackgraph_dictionary[old_current])
                
            self.visited.append(self.attackgraph_dictionary[self.start_node])
            visited_set.add(self.start_node)
        return cost, old_current

    def get_costs(self):
        """
        There is no cost attribute in the attack graph, the attack step costs are calculated separately. 
        If use_ttc is False, an existing json file with costs are loaded as a dictionary. If use_ttc is True,
        the costs are calculated from samples drawn from the ttc distribution of the attack steps.

        Return:
        - cost_dictionary: A dictionary containing all attack step ids as keys, and the cost as values.
        """
        if self.use_ttc == False:
            cost_dictionary = help_functions.load_costs_from_file()
        elif self.use_ttc == True:
            cost_dictionary = self.get_cost_from_ttc()
        return cost_dictionary

    def get_cost_from_ttc(self):
        cost_dictionary = {}
        for attackgraph_node in self.attackgraph_instance.nodes:
            ttc = attackgraph_node.ttc
            if ttc == None or ttc == {}:
                cost_dictionary[attackgraph_node.id] = 0
            elif ttc != None:
                cost_dictionary[attackgraph_node.id] = help_functions.cost_from_ttc(ttc, 100)
        return cost_dictionary
    
    def random_path(self):
        """
        Generate a random attack path in the attack graph, considering attacker cost budget and/or target node.

        This method explores a random path in the attack graph from the start node.
        It uses a random selection strategy among the attack surface nodes, considering the attacker's cost budget
        and searching for a specific target node if provided.

        Returns:
        - cost: The total cost of the random path.
        """
        self.attacker.reached_attack_steps = [self.attackgraph_dictionary[self.start_node]]
        self.visited = self.attacker.reached_attack_steps
        self.horizon = maltoolbox.attackgraph.query.get_attack_surface(self.attacker)
        horizon_set = {node.id for node in self.horizon}
        visited_set = {node.id for node in self.visited}

        costs = self.cost_dictionary
        cost = 0
        while len(horizon_set-visited_set) > 0:
            node = random.choice(list(self.horizon))

            # Attack unvisited node in the horizon.
            if node not in self.visited:

                # Check if the cost is within cost budget (if the cost budget was specified).
                if self.attacker_cost_budget != None and cost+costs[node.id] > self.attacker_cost_budget:
                    break
                
                # Find a parent node and update path.
                parent_node_id = self.start_node
                for parent_node in node.parents:
                    if parent_node in self.attacker.reached_attack_steps:
                        parent_node_id = parent_node.id
                        break
                self.path[parent_node_id].append(node)
                self.visited.append(node)
                visited_set.add(node.id)
                self.attacker.compromise(node)
                cost += costs[node.id]

                # Check if the target node was selected (if the target node was specified).
                if self.target_node != None and node.id == self.target_node:
                    break
                
                # Update attack surface.
                self.horizon = maltoolbox.attackgraph.query.get_attack_surface(self.attacker)
                horizon_set = {node.id for node in self.horizon}
        return cost

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
        # Start BFS from the start node with distance 0.
        node = self.attackgraph_dictionary[self.start_node]
        queue = deque([(node, 0)])  
        self.visited = [node]
        costs = self.cost_dictionary
        while queue:
            node, cost = queue.popleft()
            # Explore the horizon of the current node.
            for child_node in node.children:
                next_cost = cost + costs[child_node.id]
                if next_cost <= self.attacker_cost_budget:
                    self.visited.append(child_node)
                    queue.append((child_node, next_cost))
                    self.path[node.id].append(child_node)
        return cost

from dataclasses import dataclass, field

from maltoolbox.attackgraph.query import (
    get_attack_surface,
    is_node_traversable_by_attacker
)

from maltoolbox.attackgraph import Attacker, AttackGraph, AttackGraphNode
from collections import deque
import heapq
import random


def random_path_2(
        attackgraph: AttackGraph,
        start_node: AttackGraphNode,
        costs: dict[int, int],
        target_node: AttackGraphNode = None,
        attacker_cost_budget: int = None,
    ):
    """
    Generate a random attack path in the attack graph,
    considering attacker cost budget and/or target node.

    This method explores a random path in the attack graph
    from the start node. It uses a random selection strategy
    among the attack surface nodes, considering the attacker's
    cost budget and searching for a specific target node if provided.

    Returns:
    - cost: The total cost of the random path.
    """

    attacker = Attacker("RandomAttacker")
    attackgraph.add_attacker(
        attacker,
        entry_points=[start_node],
        reached_attack_steps=[start_node]
    )

    visited = [start_node]
    horizon = get_attack_surface(attacker)
    horizon_set = {node.id for node in horizon}
    visited_set = {node.id for node in visited}
    path = {node.id: [] for node in attackgraph.nodes}

    cost = 0
    while len(horizon_set - visited_set) > 0:
        node = random.choice(list(horizon))

        # Attack unvisited node in the horizon.
        if node not in visited:

            # Check if the cost is within cost budget.
            if attacker_cost_budget and cost + costs[node.id] > attacker_cost_budget:
                break

            # Find a parent node and update path.
            parent_node_id = start_node
            for parent_node in node.parents:
                if parent_node in attacker.reached_attack_steps:
                    parent_node_id = parent_node.id
                    break

            path[parent_node_id].append(node)
            visited.append(node)
            visited_set.add(node.id)
            attacker.compromise(node)
            cost += costs[node.id]

            # Check if the target node was reached.
            if target_node and node == target_node:
                break

            # Update attack surface.
            horizon = get_attack_surface(attacker)
            horizon_set = {node.id for node in horizon}

    return cost


def bfs(
        attackgraph: AttackGraph,
        start_node: AttackGraphNode,
        costs: dict[int, int],
        attacker_cost_budget: int
    ):
    """
    Perform Breadth-First Search (BFS) on an attack graph from start_node.

    This method explores the attack graph starting from specified start node,
    considering a cost budget for the attacker. It calculates the total cost
    of the paths within the budget and returns the final cost.
    Note that this method does not consider all attack graph logic.

    Returns:
    - cost: total cost of the paths explored within attacker's cost budget.
    """
    # Start BFS from the start node with distance 0.
    node = start_node
    queue = deque([(node, 0)])
    visited = [node]
    path = {node.id: [] for node in attackgraph.nodes}

    while queue:
        node, cost = queue.popleft()
        # Explore the horizon of the current node.
        for child_node in node.children:
            next_cost = cost + costs[child_node.id]
            if next_cost <= attacker_cost_budget:
                visited.append(child_node)
                queue.append((child_node, next_cost))
                path[node.id].append(child_node)
    return cost


def cheapest_compromises_to_reach(
        start_nodes: list[AttackGraphNode],
        end_node: AttackGraphNode,
        min_costs: dict[int, int]
):
    """Return list of nodes that are the optimal way to get from
    one or several start_nodes to end_node in terms of cost, assuming
    that `min_costs` contains the minimum cost to reach each node
    from the start_nodes"""

    path = [end_node]

    if end_node in start_nodes:
        return path

    if end_node.type == 'or':
        cheapest_parent = None
        cheapest_parent_cost = float('inf')
        for parent in end_node.parents:
            cost_to_parent = min_costs[parent.id]
            if cost_to_parent < cheapest_parent_cost:
                cheapest_parent = parent
                cheapest_parent_cost = cost_to_parent

        if cheapest_parent:
            path = cheapest_compromises_to_reach(
                start_nodes, cheapest_parent, min_costs
            ) + path
        else:
            path = []

    elif end_node.type == 'and':
        for parent in end_node.parents:
            if parent.is_necessary:
                path = cheapest_compromises_to_reach(
                    start_nodes, parent, min_costs
                ) + path

    return path


def multi_source_dijkstra_with_costs(
        graph: AttackGraph,
        start_nodes: list[AttackGraphNode],
        edge_costs: dict[int, int]
    ) -> tuple[int, list[AttackGraphNode]]:
    """Dijkstra with several source nodes and predefined edge costs

    Starting from one or several nodes, calculate the cost to reach
    the specified end node.
    
    Return the cost to reach the end node and the list of visited
    nodes of the optimal path"""

    @dataclass(frozen=True, order=True)
    class PriorityNode():
        """Priority node used in heap queue"""
        cost: int
        node: AttackGraphNode = field(compare=False)

        def __hash__(self):
            return hash((self.node.id))

    # Dictionary to store the minimum cost to reach each node
    min_costs = {node.id: float('inf') for node in graph.nodes}

    # Priority queue to process nodes based on the cost
    priority_queue = []

    # Initialize the priority queue with all start nodes
    for node in start_nodes:
        min_costs[node.id] = 0
        heapq.heappush(priority_queue, PriorityNode(0, node))

    # Process the nodes in the priority queue
    while priority_queue:
        current = heapq.heappop(priority_queue)
        # If the current cost is higher than recorded cost, skip the node
        if current.cost > min_costs[current.node.id]:
            continue

        # Explore the children of the current node
        for child in current.node.children:
            alt_cost = float('inf')

            if child.type == 'or':
                # cost to reach or-node is the cost to reach its parent
                # and the edge cost to reach the child
                alt_cost = current.cost + edge_costs[child.id]

            elif child.type == 'and':
                # cost to reach and-node is the cost to reach its
                # necessary parents and the edge cost to reach the child
                alt_cost = edge_costs[child.id]
                for parent in child.parents:
                    if parent.is_necessary:
                        alt_cost += min_costs[parent.id]

            # If lower cost path to child is found,
            # update and push it to the queue
            if alt_cost < min_costs[child.id]:
                min_costs[child.id] = alt_cost
                heapq.heappush(
                    priority_queue, PriorityNode(alt_cost, child)
                )

    return min_costs

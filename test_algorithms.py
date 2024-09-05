import unittest
from maltoolbox.language import LanguageClassesFactory, LanguageGraph
from maltoolbox.model import Model
from maltoolbox.attackgraph import AttackGraph, AttackGraphNode

from attack_simulation import Attacker
from traversers import (
    multi_source_dijkstra_with_costs,
    cheapest_compromises_to_reach,
    random_path
)
import constants

def print_function_name(func):
    def wrapper(*args, **kwargs):
        print(f"Running test: {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

class TestAlgorithms(unittest.TestCase):

    def setUp(self):
        # Create the language specification and LanguageClassesFactory instance.
        self.lang_graph = LanguageGraph.from_mar_archive(constants.MAR_ARCHIVE)
        lang_classes_factory = LanguageClassesFactory(self.lang_graph)

        # Create mal-toolbox Model instance.
        self.model = Model("Test Model", lang_classes_factory)

        # Only one asset created and added to model
        app1 = lang_classes_factory.ns.Application(name="Application1")
        self.model.add_asset(app1)

        # Generate mal-toolbox AttackGraph.
        self.attackgraph = AttackGraph(self.lang_graph, self.model)
        for node in self.attackgraph.nodes:
            if node.type == 'defense':
                node.is_necessary = False
                node.is_viable = True

    @print_function_name
    def test_dijkstra_1_step(self):
        """Test dijkstra from a source which neighbors the target.
        This should result in a total cost of the target nodes cost."""

        source_node = self.attackgraph.get_node_by_full_name(
            "Application1:physicalAccessAchieved")
        target_node = self.attackgraph.get_node_by_full_name(
            "Application1:softwareProductVulnerabilityPhysicalAccessAchieved")

        # Act
        edge_costs = {n.id: float('inf') for n in self.attackgraph.nodes}
        edge_costs[target_node.id] = 2

        # Run dijkstra
        min_costs = multi_source_dijkstra_with_costs(
            self.attackgraph, [source_node], edge_costs)
        assert min_costs[source_node.id] == 0
        assert min_costs[target_node.id] == edge_costs.get(target_node.id)

        visited = cheapest_compromises_to_reach(
            [source_node], target_node, min_costs)
        assert visited == [source_node, target_node]

    @print_function_name
    def test_dijkstra_2_source_nodes_to_and_node(self):
        """

            Node0           Node1
              |               |
              |               |
            Node2           Node3
               \             /
                \           /
                 \         /
                    Node4
                    (and)
        """

        node0 = AttackGraphNode('or', 'Node0')
        node1 = AttackGraphNode('or', 'Node1')
        node2 = AttackGraphNode('or', 'Node2', parents=[node0], is_necessary=True)
        node3 = AttackGraphNode('or', 'Node3', parents=[node1], is_necessary=True)
        node4 = AttackGraphNode('and', 'Node4', parents=[node2, node3])
        node0.children = [node2]
        node1.children = [node3]
        node2.children = [node4]
        node3.children = [node4]

        graph = AttackGraph()
        for node in (node0, node1, node2, node3, node4):
            graph.add_node(node)

        edge_costs = {
            node0.id: 1,
            node1.id: 2,
            node2.id: 4,
            node3.id: 8,
            node4.id: 16
        }

        # Create the attacker and compromise entrypoints
        source_nodes = [node0, node1]
        target_node = node4

        min_costs = multi_source_dijkstra_with_costs(
            graph, source_nodes, edge_costs)

        for source_node in source_nodes:
            assert min_costs[source_node.id] == 0

        assert min_costs[target_node.id] == (
            edge_costs[node2.id]
            + edge_costs[node3.id]
            + edge_costs[node4.id]
        )

        visited = cheapest_compromises_to_reach(
            source_nodes, target_node, min_costs)
        assert visited == [node1, node3, node0, node2, node4]

    @print_function_name
    def test_dijkstra_2_steps(self):
        """Test dijkstra from a source two steps from the target.
        This should result in a total cost of the paths cost."""

        source_node = self.attackgraph.get_node_by_full_name(
            "Application1:fullAccess")
        middle_node = self.attackgraph.get_node_by_full_name(
            "Application1:attemptDeny")
        target_node = self.attackgraph.get_node_by_full_name(
            "Application1:successfulDeny")

        edge_costs = {
            node.id: float('inf') for node in self.attackgraph.nodes
        }
        edge_costs[middle_node.id] = 4
        edge_costs[target_node.id] = 8

        # Run dijkstra
        min_costs = multi_source_dijkstra_with_costs(
            self.attackgraph, [source_node], edge_costs)
        assert min_costs[source_node.id] == 0
        assert min_costs[target_node.id] == \
            edge_costs[middle_node.id] + edge_costs[target_node.id]

        visited = cheapest_compromises_to_reach(
            [source_node], target_node, min_costs)
        assert visited == [source_node, middle_node, target_node]

    @print_function_name
    def test_dijkstra_3_steps(self):
        """Test dijkstra from a source two steps from the target.
        This should result in a total cost of the paths cost."""

        source_node = self.attackgraph.get_node_by_full_name(
            "Application1:fullAccess")
        second_node = self.attackgraph.get_node_by_full_name(
            "Application1:attemptDeny")
        third_node = self.attackgraph.get_node_by_full_name(
            "Application1:successfulDeny")
        target_node = self.attackgraph.get_node_by_full_name(
            "Application1:deny")

        # Act
        edge_costs = {
            node.id: float('inf') for node in self.attackgraph.nodes
        }

        edge_costs[second_node.id] = 4
        edge_costs[third_node.id] = 8
        edge_costs[target_node.id] = 16

        # Run dijkstra
        min_costs = multi_source_dijkstra_with_costs(
            self.attackgraph, [source_node], edge_costs)
        assert min_costs[source_node.id] == 0
        assert min_costs[target_node.id] == (
            edge_costs[second_node.id]
            + edge_costs[third_node.id]
            + edge_costs[target_node.id]
        )

        visited = cheapest_compromises_to_reach(
            [source_node], target_node, min_costs)
        assert visited == [source_node, second_node, third_node, target_node]

    @print_function_name
    def test_dijkstra_3_steps_with_and(self):
        """Test dijkstra from a source two steps from the target.
        This should result in a total cost of the paths cost."""

        source_node_1 = self.attackgraph.get_node_by_full_name( # or
                "Application1:attemptUnsafeUserActivity")
        source_node_2 = self.attackgraph.get_node_by_full_name( # or
                "Application1:reverseReach")
        source_nodes = [source_node_1, source_node_2]

        second_node = self.attackgraph.get_node_by_full_name( # and
            "Application1:attackerUnsafeUserActivityCapabilityWithReverseReach")
        third_node = self.attackgraph.get_node_by_full_name( # or
            "Application1:attackerUnsafeUserActivityCapability")
        target_node = self.attackgraph.get_node_by_full_name( # and
            "Application1:successfulUnsafeUserActivity")

        edge_costs = {
            node.id: float('inf') for node in self.attackgraph.nodes
        }
        edge_costs[source_node_1.id] = 0
        edge_costs[source_node_2.id] = 0
        edge_costs[second_node.id] = 2
        edge_costs[third_node.id] = 4
        edge_costs[target_node.id] = 8

        # Run dijkstra
        min_costs = multi_source_dijkstra_with_costs(
            self.attackgraph, source_nodes, edge_costs)

        for source_node in source_nodes:
            assert min_costs[source_node.id] == 0

        assert min_costs[target_node.id] == (
            edge_costs[second_node.id]
            + edge_costs[third_node.id]
            + edge_costs[target_node.id]
        )

        visited = cheapest_compromises_to_reach(
            source_nodes, target_node, min_costs)
        assert visited == [
            source_node_1, source_node_2, second_node,
            third_node, source_node_1, target_node
        ]

    @print_function_name
    def test_random_path_with_target_deterministic(self):
        """Test random path traverser for a path that can't go wrong"""

        source_node = self.attackgraph.get_node_by_full_name( # or
            "Application1:attemptUnsafeUserActivity")

        second_node = self.attackgraph.get_node_by_full_name( # and
            "Application1:attackerUnsafeUserActivityCapabilityWithoutReverseReach")

        third_node = self.attackgraph.get_node_by_full_name( # or
            "Application1:attackerUnsafeUserActivityCapability")

        target_node = self.attackgraph.get_node_by_full_name( # and
            "Application1:successfulUnsafeUserActivity")

        edge_costs = {
            node.id: float('inf') for node in self.attackgraph.nodes
        }

        edge_costs[source_node.id] = 0
        edge_costs[second_node.id] = 0
        edge_costs[third_node.id] = 0
        edge_costs[target_node.id] = 0

        cost, visited = random_path(
            self.attackgraph,
            source_node,
            edge_costs,
            target_node=target_node
        )
        assert cost == 0
        assert visited == [source_node, second_node, third_node, target_node]

    @print_function_name
    def test_random_path_with_target_impossible(self):
        """Random path when there is no possible next step from source"""

        source_node = self.attackgraph.get_node_by_full_name( # or
            "Application1:softwareCheck")

        target_node = self.attackgraph.get_node_by_full_name( # and
            "Application1:fullAccess")

        edge_costs = {
            node.id: 1 for node in self.attackgraph.nodes
        }

        cost, visited = random_path(
            self.attackgraph,
            source_node,
            edge_costs,
            target_node=target_node
        )
        assert cost == 0
        assert visited == [source_node]

    @print_function_name
    def test_random_path_with_budget_deterministic(self):
        """Test random path traverser for a path that can't go wrong"""

        source_node = self.attackgraph.get_node_by_full_name( # or
            "Application1:attemptUnsafeUserActivity")

        second_node = self.attackgraph.get_node_by_full_name( # and
            "Application1:attackerUnsafeUserActivityCapabilityWithoutReverseReach")

        third_node = self.attackgraph.get_node_by_full_name( # or
            "Application1:attackerUnsafeUserActivityCapability")

        target_node = self.attackgraph.get_node_by_full_name( # and
            "Application1:successfulUnsafeUserActivity")

        edge_costs = {
            node.id: float('inf') for node in self.attackgraph.nodes
        }

        edge_costs[source_node.id] = 1
        edge_costs[second_node.id] = 1
        edge_costs[third_node.id] = 1
        edge_costs[target_node.id] = 1

        # Budget 1 will reach only the second node
        cost, visited = random_path(
            self.attackgraph,
            source_node,
            edge_costs,
            target_node=target_node,
            attacker_cost_budget=1
        )
        assert cost == 1
        assert visited == [source_node, second_node]

        # Budget 2 will reach the second node
        cost, visited = random_path(
            self.attackgraph,
            source_node,
            edge_costs,
            target_node=target_node,
            attacker_cost_budget=2
        )
        assert cost == 2
        assert visited == [source_node, second_node, third_node]

        # Budget 3 will reach the target
        cost, visited = random_path(
            self.attackgraph,
            source_node,
            edge_costs,
            target_node=target_node,
            attacker_cost_budget=3
        )
        assert cost == 3
        assert visited == [source_node, second_node, third_node, target_node]

        # Infinite budget, but still only uses up 3
        cost, visited = random_path(
            self.attackgraph,
            source_node,
            edge_costs,
            target_node=target_node,
            attacker_cost_budget=float('inf')
        )
        assert cost == 3
        assert visited == [source_node, second_node, third_node, target_node]

    @print_function_name
    def test_random_path_with_budget_no_targets(self):
        """Test random path traverser"""

        source_node = self.attackgraph.get_node_by_full_name( # or
            "Application1:attemptUnsafeUserActivity")

        edge_costs = {
            node.id: 1 for node in self.attackgraph.nodes
        }

        # Budget will affect reach
        for given_budget in range(10):
            cost, visited = random_path(
                self.attackgraph,
                source_node,
                edge_costs,
                attacker_cost_budget=given_budget
            )
            assert cost == given_budget
            assert len(visited) == given_budget + 1



if __name__ == '__main__':
    unittest.main()

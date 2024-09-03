import unittest
from maltoolbox.language import LanguageClassesFactory, LanguageGraph
from maltoolbox.model import Model
from maltoolbox.attackgraph import AttackGraph, AttackGraphNode
from maltoolbox.attackgraph.analyzers.apriori import evaluate_viability_and_necessity

from attack_simulation import AttackSimulation, Attacker
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

        # Create the attack simulation
        attack_simulation = AttackSimulation(self.attackgraph)

        # Create the attacker and compromise entrypoints
        attacker = Attacker("DijkstraAttacker")
        self.attackgraph.add_attacker(attacker)
        attacker.compromise(source_node)

        # Run dijkstra
        min_cost, visited = attack_simulation.multi_source_dijkstra_with_costs(
            self.attackgraph,
            [source_node],
            target_node,
            edge_costs
        )

        assert visited == [source_node, target_node]
        assert min_cost == edge_costs.get(target_node.id)

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

        # Create the attack simulation
        attack_simulation = AttackSimulation(graph)
        min_cost, visited = attack_simulation.multi_source_dijkstra_with_costs(
            graph, source_nodes, target_node, edge_costs)

        assert min_cost == 4 + 8 + 16
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

        # Create the attack simulation
        attack_simulation = AttackSimulation(self.attackgraph)

        # Run dijkstra
        cost, visited = attack_simulation.multi_source_dijkstra_with_costs(
            self.attackgraph,
            [source_node],
            target_node,
            edge_costs
        )

        assert visited == [source_node, middle_node, target_node]
        assert cost == edge_costs[middle_node.id] + edge_costs[target_node.id]

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

        # Create the attack simulation
        attack_simulation = AttackSimulation(self.attackgraph)

        # Run dijkstra
        cost, visited = attack_simulation.multi_source_dijkstra_with_costs(
            self.attackgraph,
            [source_node],
            target_node,
            edge_costs
        )

        assert visited == [source_node, second_node, third_node, target_node]
        assert cost == (
            edge_costs[second_node.id]
            + edge_costs[third_node.id]
            + edge_costs[target_node.id]
        )

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

        # Create the attack simulation
        attack_simulation = AttackSimulation(self.attackgraph)

        # Run dijkstra
        cost, visited = attack_simulation.multi_source_dijkstra_with_costs(
            self.attackgraph,
            source_nodes,
            target_node,
            edge_costs
        )

        assert visited == [
            source_node_1, source_node_2, second_node, third_node, source_node_1, target_node
        ]
        assert cost == (
            edge_costs[second_node.id]
            + edge_costs[third_node.id]
            + edge_costs[target_node.id]
        )


if __name__ == '__main__':
    unittest.main()

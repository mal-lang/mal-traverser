import unittest
from maltoolbox.language import LanguageClassesFactory, LanguageGraph
from maltoolbox.model import Model
from maltoolbox.attackgraph import AttackGraph
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

        self.attackgraph.save_to_file('tmp/ag.json')


    @print_function_name
    def test_dijkstra_1_step(self):
        """Test dijkstra from a source which neighbors the target.
        This should result in a total cost of the target nodes cost."""

        source_node = self.attackgraph.get_node_by_full_name(
            "Application1:physicalAccessAchieved")
        target_node = self.attackgraph.get_node_by_full_name(
            "Application1:softwareProductVulnerabilityPhysicalAccessAchieved")

        # Act
        costs = {
            source_node.full_name: 1,
            target_node.full_name: 2
        }

        # Create the attack simulation
        attack_simulation = AttackSimulation(self.attackgraph, costs=costs)

        # Run dijkstra
        cost = attack_simulation.dijkstra(
            self.attackgraph,
            source_node=source_node,
            target_node=target_node
        )

        # Assertions
        visited = set(
            [node.full_name for node in attack_simulation.visited]
        )
        assert visited == {
            source_node.full_name, target_node.full_name
        }
        assert cost == costs.get(
            "Application1:softwareProductVulnerabilityPhysicalAccessAchieved"
        )

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

        # Act
        costs = {
            node.full_name: 1 for node in self.attackgraph.nodes
        }
        costs[source_node.full_name] = 2
        costs[middle_node.full_name] = 4
        costs[target_node.full_name] = 8

        # Create the attack simulation
        attack_simulation = AttackSimulation(self.attackgraph, costs=costs)

        # Run dijkstra
        cost = attack_simulation.dijkstra(
            self.attackgraph,
            source_node=source_node,
            target_node=target_node
        )

        # Assertions
        visited = set(
            [node.full_name for node in attack_simulation.visited]
        )

        assert visited == {
            source_node.full_name,
            middle_node.full_name,
            target_node.full_name
        }
        assert cost == \
            costs[middle_node.full_name] + costs[target_node.full_name]


if __name__ == '__main__':
    unittest.main()

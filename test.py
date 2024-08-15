import unittest

from maltoolbox.language import LanguageGraph, LanguageClassesFactory
from maltoolbox.model import Model
from maltoolbox.attackgraph import Attacker, AttackGraph

# Custom files.
import constants
import help_functions
from attack_simulation import AttackSimulation

def print_function_name(func):
    def wrapper(*args, **kwargs):
        print(f"Running test: {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

class TestAttackSimulation(unittest.TestCase):

    def setUp(self):
        # Create the language specification and LanguageClassesFactory instance.
        self.lang_graph = LanguageGraph.from_mar_archive(constants.MAR_ARCHIVE)
        lang_classes_factory = LanguageClassesFactory(self.lang_graph)

        # Create mal-toolbox Model instance.
        self.model = Model.load_from_file(constants.MODEL_FILE, lang_classes_factory)

        # Generate mal-toolbox AttackGraph.
        self.attackgraph = AttackGraph(self.lang_graph, self.model)

        # Change nodes with type 'defense' so that is_necessary=False, for testing purposes.
        for node in self.attackgraph.nodes:
            if node.type == 'defense':
                node.is_necessary = False
                node.is_viable = True

        # Add the attacker.
        self.model.attackers = []
        attacker_id = 1
        attacker_name = "Attacker1"
        attacker = Attacker(attacker_name)
        self.model.add_attacker(attacker, attacker_id)
        self.model.attackers[0].entry_points = []

    @print_function_name
    def test_shortest_path_on_1_step_or_path(self):
        # Arrange
        target_attack_step = self.attackgraph.get_node_by_full_name("Credentials:6:attemptCredentialsReuse").id
        entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse"]], [8, ["attemptCredentialsReuse"]]]
        actual_cost = 4

        expected_visited_full_names = {"Credentials:6:attemptCredentialsReuse"}
        expected_visited_ids = {
             self.attackgraph.get_node_by_full_name(name).id
             for name in expected_visited_full_names
        }

        self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
        self.attackgraph.attach_attackers()
        attacker = self.attackgraph.attackers[0]
        
        # Act
        attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
        attack_simulation.set_target_node(target_attack_step)
        cost = attack_simulation.dijkstra()
        visited = set([node.id for node in attack_simulation.visited])

        # Assert
        self.assertEqual(cost, actual_cost)
        expected_visited_ids.add(attack_simulation.start_node)
        self.assertEqual(visited, expected_visited_ids)

    @print_function_name
    def test_shortest_path_on_6_step_with_and_in_path(self):
        # Arrange
        target_attack_step = self.attackgraph.get_node_by_full_name("OS App:fullAccess").id
        entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse", "attemptFullAccessFromSupplyChainCompromise"]], [8, ["attemptCredentialsReuse"]]]
        actual_cost = 19
        expected_visited_full_names = {"OS App:attemptFullAccessFromSupplyChainCompromise", "OS App:bypassSupplyChainAuditing", "OS App:supplyChainAuditingBypassed", "OS App:fullAccessFromSupplyChainCompromise", "OS App:fullAccess"}
        expected_visited_ids = {
             self.attackgraph.get_node_by_full_name(name).id
             for name in expected_visited_full_names
        }

        self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
        self.attackgraph.attach_attackers()
        attacker = self.attackgraph.attackers[0]
        
        # Act
        attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
        attack_simulation.set_target_node(target_attack_step)
        cost = attack_simulation.dijkstra()
        visited = set([node.id for node in attack_simulation.visited])
        
        # Assert
        self.assertEqual(cost, actual_cost)
        expected_visited_ids.add(attack_simulation.start_node)
        self.assertEqual(visited, expected_visited_ids)
   
    @print_function_name
    def test_shortest_path_on_14_step_path(self):
        # Arrange
        target_attack_step = self.attackgraph.get_node_by_full_name("Credentials:9:propagateOneCredentialCompromised").id
        entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse", "attemptFullAccessFromSupplyChainCompromise"]], [8, ["attemptCredentialsReuse"]]]
        actual_cost = 79
        expected_visited_full_names = {"Credentials:6:attemptCredentialsReuse", "Credentials:6:credentialsReuse", "Credentials:6:attemptUse", "Credentials:6:use", "Credentials:6:attemptPropagateOneCredentialCompromised", \
                                        "Credentials:6:propagateOneCredentialCompromised", "User:11:oneCredentialCompromised", "User:11:passwordReuseCompromise", "Credentials:9:attemptCredentialsReuse", "Credentials:9:credentialsReuse", \
                                        "Credentials:9:attemptUse", "Credentials:9:use", "Credentials:9:attemptPropagateOneCredentialCompromised", "Credentials:9:propagateOneCredentialCompromised"}
        expected_visited_ids = {self.attackgraph.get_node_by_full_name(name).id for name in expected_visited_full_names}

        self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
        self.attackgraph.attach_attackers()
        attacker = self.attackgraph.attackers[0]
        
        # Act
        attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
        attack_simulation.set_target_node(target_attack_step)
        cost = attack_simulation.dijkstra()
        visited = set([node.id for node in attack_simulation.visited])

        # Assert
        self.assertEqual(cost, actual_cost)
        expected_visited_ids.add(attack_simulation.start_node)
        self.assertEqual(visited, expected_visited_ids)

    @print_function_name
    def test_shortest_path_on_unreachable_attack_step(self):
        # Arrange
        target_attack_step = self.attackgraph.get_node_by_full_name("Credentials:5:extract").id
        entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse", "attemptFullAccessFromSupplyChainCompromise"]], [8, ["attemptCredentialsReuse"]]]
        actual_cost = 0
        self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
        self.attackgraph.attach_attackers()
        attacker = self.attackgraph.attackers[0]
        
        # Act
        attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
        attack_simulation.set_target_node(target_attack_step)
        cost = attack_simulation.dijkstra()
        visited = set([node.id for node in attack_simulation.visited])

        # Assert
        self.assertEqual(cost, actual_cost)
        self.assertNotIn(target_attack_step, visited)

    @print_function_name
    def test_shortest_path_on_choice_between_2_paths_to_target(self):
        # Arrange
        target_attack_step = self.attackgraph.get_node_by_full_name("OS App:fullAccess").id
        entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse", "attemptFullAccessFromSupplyChainCompromise", "fullAccess"]], [8, ["attemptCredentialsReuse"]]]
        actual_cost = 1
        expected_visited_full_names = {"OS App:fullAccess"}
        expected_visited_ids = {
             self.attackgraph.get_node_by_full_name(name).id
             for name in expected_visited_full_names
        }

        self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
        self.attackgraph.attach_attackers()
        attacker = self.attackgraph.attackers[0]
        
        # Act
        attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
        attack_simulation.set_target_node(target_attack_step)
        cost = attack_simulation.dijkstra()
        visited = set([node.id for node in attack_simulation.visited])

        # Assert
        self.assertEqual(cost, actual_cost)
        expected_visited_ids.add(attack_simulation.start_node)
        self.assertEqual(visited, expected_visited_ids)

    @print_function_name
    def test_shortest_path_on_choice_between_4_paths_to_target(self):
        # Arrange
        target_attack_step = self.attackgraph.get_node_by_full_name("Data:4:accessDecryptedData").id
        actual_cost = 23
        entry_point_attack_steps = [[5, ["attemptCredentialTheft", "attemptReadFromReplica", "guessCredentialsFromHash", "weakCredentials"]], [6, ["attemptUse"]]]
        self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
        self.attackgraph.attach_attackers()
        attacker = self.attackgraph.attackers[0]

        node = self.attackgraph.get_node_by_full_name("Credentials:6:use")
        node.is_necessary = False

        # Act
        attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
        attack_simulation.set_target_node(target_attack_step)
        cost = attack_simulation.dijkstra()

        # Assert
        self.assertEqual(cost, actual_cost)

    @print_function_name
    def test_shortest_path_on_one_possible_path_but_5_entry_points(self):
            # Arrange
            target_attack_step = self.attackgraph.get_node_by_full_name("Data:4:accessDecryptedData").id
            actual_cost = 48
            entry_point_attack_steps = [[5, ["attemptCredentialTheft", "attemptReadFromReplica", "guessCredentialsFromHash", "weakCredentials"]], [6, ["attemptUse"]]]
            self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
            self.attackgraph.attach_attackers()
            attacker = self.attackgraph.attackers[0]

            # Act
            attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
            attack_simulation.set_target_node(target_attack_step)
            cost = attack_simulation.dijkstra()

            # Assert
            self.assertEqual(cost, actual_cost)
        
    @print_function_name
    def test_random_path_with_infinate_cost_budget_on_reachable_node(self):
        # Arrange
        target_attack_step = self.attackgraph.get_node_by_full_name("OS App:bypassSupplyChainAuditing").id
        entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse", "attemptFullAccessFromSupplyChainCompromise"]], [8, ["attemptCredentialsReuse"]]]
        self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
        self.attackgraph.attach_attackers()
        attacker = self.attackgraph.attackers[0]

        # Act
        attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
        attack_simulation.set_target_node(target_attack_step)
        cost = attack_simulation.random_path()

        # Assert
        self.assertGreater(cost, 0)
        self.assertIn(attack_simulation.attackgraph_dictionary[target_attack_step], attack_simulation.visited)

    @print_function_name
    def test_random_path_with_infinate_cost_budget_on_unreachable_node(self):
        # Arrange
        target_attack_step = self.attackgraph.get_node_by_full_name("Credentials:8:extract").id
        entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse"]], [8, ["attemptCredentialsReuse"]]]
        self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
        self.attackgraph.attach_attackers()
        attacker = self.attackgraph.attackers[0]

        # Act
        attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
        attack_simulation.set_target_node(target_attack_step)
        cost = attack_simulation.random_path()

        # Assert
        self.assertGreater(cost, 0)
        self.assertNotIn(attack_simulation.attackgraph_dictionary[target_attack_step], attack_simulation.visited)

    @print_function_name
    def test_random_path_with_infinate_cost_budget_on_reachable_node_containing_and_step(self):
            # Arrange
            target_attack_step = self.attackgraph.get_node_by_full_name("OS App:fullAccessFromSupplyChainCompromise").id
            entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse", "attemptFullAccessFromSupplyChainCompromise"]], [8, ["attemptCredentialsReuse"]]]
            optimal_cost = 19
            self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
            self.attackgraph.attach_attackers()
            attacker = self.attackgraph.attackers[0]

            # Act
            attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
            attack_simulation.set_target_node(target_attack_step)
            cost = attack_simulation.random_path()

            # Assert
            self.assertGreater(cost, optimal_cost)
            self.assertIn(attack_simulation.attackgraph_dictionary[target_attack_step], attack_simulation.visited)

    @print_function_name
    def test_random_path_with_restricted_cost_budget_on_reachable_target_node(self):
            # Arrange
            target_attack_step = self.attackgraph.get_node_by_full_name("Credentials:9:propagateOneCredentialCompromised").id
            attacker_cost_budget = 1
            entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse", "attemptFullAccessFromSupplyChainCompromise"]], [8, ["attemptCredentialsReuse"]]]
            self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
            self.attackgraph.attach_attackers()
            attacker = self.attackgraph.attackers[0]

            # Act
            attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
            attack_simulation.set_attacker_cost_budget(attacker_cost_budget)
            attack_simulation.set_target_node(target_attack_step)
            cost = attack_simulation.random_path()

            # Assert
            self.assertLessEqual(cost, attacker_cost_budget)
            self.assertNotIn(attack_simulation.attackgraph_dictionary[target_attack_step], attack_simulation.visited)

    @print_function_name
    def test_random_path_with_cost_budget_and_no_target_node(self):
                # Arrange
                attacker_cost_budget = 10
                entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse", "attemptFullAccessFromSupplyChainCompromise"]], [8, ["attemptCredentialsReuse"]]]
                self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
                self.attackgraph.attach_attackers()
                attacker = self.attackgraph.attackers[0]

                # Act
                attack_simulation = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
                attack_simulation.set_attacker_cost_budget(attacker_cost_budget)
                cost = attack_simulation.random_path()

                # Assert
                self.assertLessEqual(cost, attacker_cost_budget)
    
    @print_function_name
    def test_random_path_with_infinate_cost_budget_and_no_target_node(self):
                # Arrange
                entry_point_attack_steps = [[5, ["attemptCredentialsReuse"]], [6, ["attemptCredentialsReuse", "guessCredentials"]], [0, ["softwareProductAbuse", "attemptFullAccessFromSupplyChainCompromise"]], [8, ["attemptCredentialsReuse"]]]
                self.model = help_functions.add_entry_points_to_attacker(self.model, entry_point_attack_steps)
                self.attackgraph.attach_attackers()
                attacker = self.attackgraph.attackers[0]

                # Act
                attack_simulation_1 = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
                cost_1 = attack_simulation_1.random_path()
                attack_simulation_2 = AttackSimulation(self.attackgraph, attacker, use_ttc=False) 
                cost_2 = attack_simulation_2.random_path()

                # Assert
                self.assertEqual(cost_1, cost_2)

if __name__ == '__main__':
    unittest.main()

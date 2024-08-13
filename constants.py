
# Colors.
PINK = '\033[95m'
RED = '\033[91m'
STANDARD = '\033[0m'
BOLD = '\033[1m'

# All walker options.
ATTACK_OPTIONS = {
    "1": "step by step attack",
    "2": "shortest path with dijkstra",
    "3": "random path",
    "4": "breadth first search"
    }

# Used in AttackSimulation.step_by_step_attack_simulation().
STEP_BY_STEP_ATTACK_COMMANDS = {
    "1": "view horizon",
    "2": "action",
    "3": "exit"
    }

# Neo4j database information.
URI = "bolt://localhost:7687"
USERNAME = "neo4j"
PASSWORD = "mgg12345!"
DBNAME = "neo4j"

MODEL_FILE = "assets/model_0.1.6.json"
COST_FILE = "assets/costs.json"
MAR_ARCHIVE = "assets/org.mal-lang.coreLang-1.0.0.mar"

from typing import List
import json
import random
import numpy as np

# Custom files.
import constants

def print_dictionary(dict):
    """
    Prints the keys and values of a dictionary in custom format.
    
    Arguments:
    dict           - a dictionary
    """
    for command in dict:
        description = dict[command]
        print(f"{constants.BOLD}", "(", command, ")", end=" ")
        if type(description) == list:
            description_str = ""
            for elem in description:
                description_str += str(elem) + " "
            description = description_str
        print(f"{constants.BOLD}", description)
    print(f"{constants.STANDARD}",end="")


def calculate_cost_and_save_as_json(node_list, output_file):
    """
    Calculates the cost randomly in range of 1-10 and maps the attack step id to the cost.
    This information is then saved on file.
    
    Arguments:
    node_list       - a list of attack steps.
    output_file     - file name.
    """
    costs_dict = {}

    for node in node_list:
        node_id = node.id
        node_asset = node.asset

        if node_id is not None and node_asset != "Attacker":
            cost = random.randint(1, 10)
            costs_dict[node_id] = cost

    with open(output_file, 'w') as file:
        json.dump(costs_dict, file)

def load_costs_from_file():
    """
    Load cost from file.
    
    Return:
    costs_dict      - dictionary
    """
    try:
        with open(constants.COST_FILE, 'r') as file:
            costs_dict = json.load(file)
        return costs_dict
    except (FileNotFoundError, json.JSONDecodeError):
        # Handle file not found or invalid JSON
        return {}

def cost_from_ttc(ttc, num_samples=100):
    sum_of_samples = 0
    distribution = ttc['name']
    for _ in range(num_samples):
        sample = 0
        if distribution == "EasyAndCertain":
            # Generate sample for EasyAndCertain distribution.
            sample = process_sample({'Exponential': 1})
        elif distribution == "EasyAndUncertain":
            # Generate sample for EasyAndUncertain distribution.
            sample = process_sample({'Exponential': 1, 'Bernoulli': 0.5})
        elif distribution == "HardAndCertain":
            # Generate sample for HardAndCertain distribution.
            sample = process_sample({'Exponential': 0.1})
        elif distribution == "HardAndUncertain":
            # Generate sample for HardAndUncertain distribution.
            sample = process_sample({'Exponential': 0.1, 'Bernoulli': 0.5})
        elif distribution == "VeryHardAndCertain":
            # Generate sample for VeryHardAndCertain distribution.
            sample = process_sample({'Exponential': 0.01})
        elif distribution == "VeryHardAndUncertain":
            # Generate sample for VeryHardAndUncertain distribution.
            sample = process_sample({'Exponential': 0.01, 'Bernoulli': 0.5})
        elif distribution == "Exponential":
            # Generate sample for custom Exponential distribution.
            scale = float(ttc['arguments'][0])
            sample = process_sample({'Exponential': scale})
        sum_of_samples += sample

    cost = sum_of_samples / num_samples
    return cost

def process_sample(distribution):
    MAX_COST = 500
    # Generate a random sample for the given distribution
    if 'Bernoulli' in distribution:
        # Mixture of exponential and constant distribution
        prob = distribution['Bernoulli']
        scale = distribution['Exponential']
        scale = 1/scale
        sample = np.random.exponential(scale=scale) if np.random.choice([0, 1], p=[prob, 1 - prob]) else MAX_COST
    else:
        # Pure exponential distribution
        scale = distribution['Exponential']
        scale = 1/scale
        sample = np.random.exponential(scale=scale)
    return sample

def add_entry_points_to_attacker(model, entry_point_attack_steps, attacker_index=0):
    for asset_id, attack_steps in entry_point_attack_steps:
        asset = model.get_asset_by_id(asset_id)
        model.attackers[attacker_index].entry_points.append((asset, attack_steps))
    return model

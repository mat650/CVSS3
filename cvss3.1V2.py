def calculate_cvss_score_from_input():
    """
    Prompts the user for a CVSS vector string, then calculates and returns the CVSS base score.
    """
    vector_string = input("Enter the CVSS vector string: ").strip()

    def parse_cvss_vector(vector_str):
        metric_abbreviations = [
            'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'
        ]
        components = vector_str.split('/')
        components = components[1:] if components[0].startswith("CVSS") else components
        metric_values = {}
        for comp in components:
            metric_abbr = next((abbr for abbr in metric_abbreviations if comp.startswith(abbr)), None)
            if metric_abbr:
                metric_values[metric_abbr] = comp[len(metric_abbr)+1:]
        return metric_values

    def calculate_base_score(metrics):
        metric_weights = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
            'AC': {'L': 0.77, 'H': 0.44},
            'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},  # Values for scope unchanged
            'UI': {'N': 0.85, 'R': 0.62},
            'C': {'H': 0.56, 'L': 0.22, 'N': 0},
            'I': {'H': 0.56, 'L': 0.22, 'N': 0},
            'A': {'H': 0.56, 'L': 0.22, 'N': 0},
        }

        scope = metrics.get('S', 'U')
        if scope == 'C':
            metric_weights['PR']['L'] = 0.68  # Value if scope is changed
            metric_weights['PR']['H'] = 0.50  # Value if scope is changed

        iss = 1 - ((1 - metric_weights['C'][metrics['C']]) *
                   (1 - metric_weights['I'][metrics['I']]) *
                   (1 - metric_weights['A'][metrics['A']]))

        ess = 8.22 * metric_weights['AV'][metrics['AV']] * \
                     metric_weights['AC'][metrics['AC']] * \
                     metric_weights['PR'][metrics['PR']] * \
                     metric_weights['UI'][metrics['UI']]

        scope_changed = scope == 'C'
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02)**15
            base_score = min(1.08 * (impact + ess), 10)
        else:
            impact = 6.42 * iss
            base_score = min(impact + ess, 10)

        if iss <= 0:
            base_score = 0

        base_score = round(base_score, 1)
        return base_score

    parsed_metrics = parse_cvss_vector(vector_string)
    base_score = calculate_base_score(parsed_metrics)
    return base_score

# Pour exécuter la fonction et obtenir une entrée utilisateur, vous devez exécuter ce script localement.
# Décommentez la ligne suivante pour simuler l'appel de la fonction si vous exécutez localement.

print(f"Calculated CVSS Score: {calculate_cvss_score_from_input()}")


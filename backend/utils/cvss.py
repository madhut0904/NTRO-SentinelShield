"""
NTRO SentinelShield - CVSS v3.1 Scoring Engine
Standardized CVSS v3.1 calculator based on FIRST specification.
"""
import math

def calculate_cvss_v31(
    attack_vector: str = "N",       # Network (0.85), Adjacent (0.62), Local (0.55), Physical (0.2)
    attack_complexity: str = "L",   # Low (0.77), High (0.44)
    privileges_required: str = "L", # None (0.85/0.85), Low (0.62/0.68), High (0.27/0.50)
    user_interaction: str = "N",    # None (0.85), Required (0.62)
    scope: str = "U",               # Unchanged (U), Changed (C)
    confidentiality: str = "H",     # High (0.56), Low (0.22), None (0.0)
    integrity: str = "H",           # High (0.56), Low (0.22), None (0.0)
    availability: str = "N"         # High (0.56), Low (0.22), None (0.0)
) -> dict:
    """
    Calculates CVSS Base Score, Severity Rating, and Vector String.
    """
    # Metric values
    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_map = {"L": 0.77, "H": 0.44}
    pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_map = {"N": 0.85, "R": 0.62}
    
    c_map = {"H": 0.56, "L": 0.22, "N": 0.0}
    i_map = {"H": 0.56, "L": 0.22, "N": 0.0}
    a_map = {"H": 0.56, "L": 0.22, "N": 0.0}
    
    av = av_map.get(attack_vector.upper(), 0.85)
    ac = ac_map.get(attack_complexity.upper(), 0.77)
    ui = ui_map.get(user_interaction.upper(), 0.85)
    
    is_changed = scope.upper() == "C"
    pr = (pr_map_c if is_changed else pr_map_u).get(privileges_required.upper(), 0.62)
    
    c = c_map.get(confidentiality.upper(), 0.56)
    i = i_map.get(integrity.upper(), 0.56)
    a = a_map.get(availability.upper(), 0.0)
    
    # Impact Sub-Score (ISS)
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    
    if is_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)
    else:
        impact = 6.42 * iss
        
    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui
    
    if impact <= 0:
        base_score = 0.0
    else:
        if not is_changed:
            base_score = min(math.ceil(min(impact + exploitability, 10.0) * 10) / 10.0, 10.0)
        else:
            base_score = min(math.ceil(min(1.08 * (impact + exploitability), 10.0) * 10) / 10.0, 10.0)
            
    # Determine qualitative severity
    if base_score == 0.0:
        severity = "INFO"
    elif base_score < 4.0:
        severity = "LOW"
    elif base_score < 7.0:
        severity = "MEDIUM"
    elif base_score < 9.0:
        severity = "HIGH"
    else:
        severity = "CRITICAL"
        
    vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
    
    return {
        "score": round(base_score, 1),
        "severity": severity,
        "vector": vector,
        "impact": round(impact, 2),
        "exploitability": round(exploitability, 2)
    }

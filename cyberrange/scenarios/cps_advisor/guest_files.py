"""guest_files.py — the deploy manifest of the cps-advisor scenario: empty.

Every scenario declares here what it copies into its containers. This one
copies nothing of its own: it deploys the lab of the cps scenario, whose
manifests (cyberrange/scenarios/cps/guest_files.py) already stage the SOC's
operator API with the rest of the SOC. Declaring them again here would count
the same guest files under two scenarios.
"""

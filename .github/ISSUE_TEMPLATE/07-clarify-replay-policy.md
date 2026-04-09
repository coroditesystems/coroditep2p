# Clarify Replay Policy

## Replay Attack Policy

In our system, the policy regarding replay attacks is designed to ensure that all actions can be traced and determined to be valid. A replay attack is when a valid data transmission is maliciously repeated or delayed. In order to mitigate such attacks, the following measures are in place:

1. **Nonce Usage**: Each transaction includes a unique nonce to ensure that each request is unique.
2. **Timestamp Verification**: Each transaction is timestamped to ensure it is processed within a specific time frame.
3. **Session Handling**: Sessions are time-limited, and any requests made after a session expires will be treated as potential replay attacks.

## Ban Semantics

If a replay attack is detected, the consequences include:
- Immediate ban of the user's account involved in the attack.
- Logging of the incident for future reference and analysis.
- Notification to the user about the ban and the reason behind it.

We take the integrity of our system seriously and employ multiple layers of security to prevent replay attacks and ensure all transactions are legitimate.
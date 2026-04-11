# rule_engine.py

from models import Rule, RuleAction
from db import SessionLocal
from graph import forward_email, delete_email, move_email_to_folder
from datetime import datetime

def apply_rules(user_id: str, session_id: str, email):
    db = SessionLocal()

    # Fetch all rules from the database
    rules = db.query(Rule).all()

    for rule in rules:
        # Check if the condition is met (subject or body)
        if rule.condition in email['subject'] or rule.condition in email['body']:
            # Move action
            if rule.action == RuleAction.MOVE:
                # Make sure that the rule contains a valid folder ID (not name)
                if rule.target_folder:  # Folder ID must be valid
                    move_email_to_folder(user_id, session_id, email['id'], rule.target_folder)
                else:
                    print(f"🚨 Invalid folder ID for MOVE action in rule {rule.id}. Skipping...")
            # Delete action
            elif rule.action == RuleAction.DELETE:
                delete_email(user_id, session_id, email['id'])
            # Forward action
            elif rule.action == RuleAction.FORWARD:
                forward_email(user_id, session_id, email['id'], rule.forward_to)

    db.close()
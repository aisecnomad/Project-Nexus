# Labs

Hands-on notebooks for the platforms ShadowScan reconciles against. They
create real cloud resources: run them in sandbox accounts and projects, and
keep credentials in your environment rather than in cells.

| Lab | What it does | Time |
| --- | --- | --- |
| [`agent-registry-lab.ipynb`](agent-registry-lab.ipynb) | Defines an agent with an A2A agent card, registers it in AWS Agent Registry (registry, record, approval) and in the Agent Registry of Gemini Enterprise Agent Platform (service and derived agent), discovers it as a consumer, and deletes everything. | about 15 minutes |

## Running the agent registry lab

```bash
pip install jupyterlab "boto3>=1.43.68" "google-cloud-agentregistry>=0.1.2" google-auth
gcloud auth application-default login          # Google Cloud
export AWS_REGION=us-east-1                    # or another Agent Registry launch Region
export GOOGLE_CLOUD_PROJECT=my-sandbox-project
jupyter lab examples/labs/agent-registry-lab.ipynb
```

Optional settings: `GOOGLE_CLOUD_LOCATION` (default `us-central1`) and
`AGENT_URL`, the A2A endpoint of a real agent to put into the card. Part A
(AWS) and Part B (Google Cloud) are independent; the last cell deletes the
registry, the record and the service.

The lab registers an agent card; it does not deploy a runtime. ShadowScan's
`cloud.aws` and `cloud.gcp` connectors observe deployed runtimes and do not
read either registry, so a registry entry without a deployment produces no
finding. See the [cloud connector guide](../../docs/connectors/cloud.md) and
the [sanctioned inventory](../../docs/inventory.md) documentation for how
deployed agents are reconciled.

"""ShadowScan: discover shadow AI agents across your organisation.

Surfaces covered:

* code repositories (local trees, GitHub, GitLab)
* identity providers (Okta, Microsoft Entra ID, Google Workspace, Auth0) and JWTs
* LLM inference gateway logs (LiteLLM, Portkey, Kong, Cloudflare, Bedrock, Azure OpenAI, Vertex, generic)
* low-code platforms & copilots (Power Platform/Copilot Studio, Salesforce Agentforce, ServiceNow, n8n, Make, Zapier, Workato)
* SaaS applications (Slack, Microsoft Teams, GitHub Apps, Atlassian, Notion, Zoom, Google Workspace)
* cloud accounts (AWS, GCP, Azure, Oracle Cloud)

Detection is signature driven: see :mod:`shadowscan.signatures`.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]

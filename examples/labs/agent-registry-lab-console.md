# Lab guide: registering an AI agent, console edition

*For AI governance students. No code, no command line: everything happens in the AWS and Google
Cloud web consoles.*

Organizations are starting to keep **agent registries**: official catalogs of the AI agents that are
allowed to operate, who owns them, what they can do, and whether someone approved them. In this lab
you play the three roles that meet around such a registry, on the two major cloud platforms:

| Role | What the role does | Where you do it in this lab |
| --- | --- | --- |
| **Publisher** | Describes an agent and submits it for registration | Part A2 (AWS), Part B1 (Google Cloud) |
| **Curator** | Reviews the submission, approves or rejects it with a reason, retires old entries | Part A3 and A5 (AWS) |
| **Consumer** | Looks for an approved agent to use, or audits what exists | Part A4 (AWS), Part B2 (Google Cloud) |

**Time:** about 45 minutes for both platforms, plus discussion. **Cost:** cents; the lab deletes
what it creates. **You need:** a login to a sandbox AWS account and to a sandbox Google Cloud project
prepared by your instructor (see *Instructor preparation* at the end).

## Learning objectives

After the lab you can

1. explain what an agent registry records and what it does *not* prove,
2. walk an agent entry through draft, review, approval, discovery and retirement,
3. name the governance controls each platform offers (approval gate, separation of duties,
   access to discovery, lifecycle states, audit trail), and
4. compare the AWS and Google Cloud models and spot the gap between "registered" and "running".

## Concepts in plain language

* **Agent.** Software that uses an AI model to perform tasks on its own, often by calling tools and
  other systems. Example: an assistant that answers questions about the holiday calendar.
* **Agent card.** A short, structured description of an agent in the open A2A ("agent-to-agent")
  format: name, purpose, address, version and skills. Think of it as the agent's business card. Both
  platforms accept it as the registration form. You will paste a ready-made card (Appendix A).
* **Registry versus runtime.** The registry is the catalog; the runtime is where the agent actually
  runs. A catalog entry does not make an agent exist, and a running agent may be missing from the
  catalog. The last part of the lab is about that gap.
* **AWS Agent Registry.** Part of Amazon Bedrock AgentCore. You create a *registry* (a catalog for one
  AWS account and Region), then *records* inside it, one per agent or tool. Records move through
  **Draft → Pending approval → Approved**, and later **Deprecated** when retired. Consumers only ever
  see approved records.
* **Agent Registry of Gemini Enterprise Agent Platform.** Google Cloud's catalog, kept per project.
  Agents built or registered inside the **Gemini Enterprise** app are added to it automatically;
  developers can also register agents directly through the API. Access is controlled with roles
  that separate readers from administrators.

## Part A: AWS Agent Registry

Sign in to the AWS console with the lab login. In the Region selector (top right) choose the Region
your instructor named; Agent Registry is available in US East (N. Virginia), US West (Oregon),
Europe (Ireland), Asia Pacific (Tokyo) and Asia Pacific (Sydney).

### A1. Create the registry (Curator)

1. In the console search bar type **AgentCore** and open **Amazon Bedrock AgentCore**.
2. In the left navigation pane, under **Discover**, choose **Registry**.
3. In the **Registries** section choose **Create registry**.
4. Fill in the form:
   * **Name:** `gov-lab-registry-` followed by your initials, for example `gov-lab-registry-ab`.
   * **Additional details → Description:** `AI governance lab. Delete after the session.`
   * **Discovery Authorization:** keep **AWS IAM** (consumers use their AWS login to search).
   * **Record approval:** make sure **Auto-approval** is **off**. This is the approval gate the lab
     is about; with it on, submissions would be approved without a curator.
   * Leave the encryption settings at their default.
5. Choose **Create registry**. The registry first shows the status *Creating*, then *Ready*; refresh
   the page after a minute if needed.

**Checkpoint.** Note the registry's name and its ARN (the long identifier starting with
`arn:aws:agent-registry:`). It is the identity an auditor would cite.

> **Governance note.** Two decisions were made just now, and both belong in a policy: *who may
> search the catalog* (the discovery authorization) and *whether a human approves entries* (the
> approval setting). Neither decision is visible to the people who later submit agents.

### A2. Register an agent (Publisher)

1. Open your registry and go to the **Registry records** section, then choose **Create record**.
2. For the source choose **Manual**. (The alternative, *Synchronize from endpoint*, lets the registry
   read the card from a running agent's address; our lab agent has no running address.)
3. Fill in the record:
   * **Name:** `holiday-helper-` followed by your initials.
   * **Display name:** `Holiday Helper`.
   * **Description:** `Answers employee questions about the company holiday calendar.`
   * **Record type:** **Agent** (an A2A agent card). The other types are MCP server, Skill, Custom
     and Gateway.
   * **Version:** `1.0.0`.
   * In the agent card editor paste the card from Appendix A, after replacing every `STUDENT` with
     your initials. The console validates the text against the official schema; use
     **Show official schema** if it reports an error, and check for a missing comma or quote.
4. Choose **Create and submit for approval**. (*Create as draft* would park the record for later.)
5. The record appears with the status *Creating*, then *Draft*, then **Pending approval**. Refresh
   the list if it does not update by itself.

**Checkpoint.** The counters at the top of the records list now show one pending approval.

> **Governance note.** The publisher wrote the description that curators and consumers will rely
> on. Nothing checked whether it is true. What evidence would you want attached to a real
> submission: an owner, a data classification, a risk assessment, a test report?

### A3. Review and approve (Curator)

If your class works in pairs, swap seats now: the curator should not be the person who submitted.

1. In the **Registry records** list select the record that is *Pending approval*.
2. Open the record and read the description and the agent card: the address it claims to live at, the
   skills it claims to have, the version.
3. Choose **Update status**, then **Approve**. The console asks for a reason. Write one a future
   auditor would understand, for example `Reviewed card and owner on 2026-10-03; pilot scope HR only`.
4. Confirm. The status changes to **Approved**.

To see the other branch, create a second record (repeat A2 with the name `holiday-helper-2-` and your
initials) and **Reject** it with the reason `Duplicate of holiday-helper`. The reason is mandatory
either way: the registry forces the reviewer to leave a trail.

> **Governance note.** Approval here is a status change plus a written reason. The platform keeps
> who changed the status and when (the record's *updated* time, and the API call in AWS CloudTrail).
> It does not test the agent. Approval means "someone accountable looked at the description".

### A4. Discover the agent (Consumer)

1. Open the registry's **Browse approved records** page, which shows what consumers see.
2. Find *Holiday Helper*. The rejected record is absent, and so is any record still pending.
3. Use the search box with a plain question such as `who can tell me about holidays`. Search ranks
   approved records by meaning, not only by exact words.
4. Open the record and look at the agent card again: this is what another agent or an IDE would
   download before calling the agent.

> **Governance note.** Discovery is itself a permission. With *AWS IAM* authorization, only AWS
> identities allowed to search this registry can see the catalog; the same catalog can also be read
> by other agents through an MCP endpoint. Decide who those identities are before the catalog grows.

### A5. Retire the agent (Curator)

1. Select the approved *Holiday Helper* record, choose **Update status**, then **Deprecate**, with the
   reason `Pilot ended`.
2. Return to **Browse approved records**: the agent has disappeared for consumers, while the record
   and its history remain visible to curators.

Deprecated is final: a deprecated record cannot be edited or re-approved. A new version would be a new
submission that goes through review again.

## Part B: Gemini Enterprise Agent Platform

Sign in to the Google Cloud console with the lab login and select the sandbox project from the
project picker at the top. Choose one of the two ways to create an agent; both end up in the same
registry.

### B1. Create or register an agent (Publisher)

**Option 1, build a no-code agent in Gemini Enterprise.** Available when the sandbox has a Gemini
Enterprise edition with Agent Designer (your instructor will say).

1. Open the Gemini Enterprise app at the address your instructor gave you.
2. In the navigation panel select **Agents**, then **+ Create agent**.
3. Describe the agent in one or two sentences, for example: *You answer employee questions about the
   company holiday calendar. If you do not know, say so and point to HR.* Select **Submit**.
4. Agent Designer drafts a name, description and instructions. Rename it `Holiday Helper` followed by
   your initials and keep the rest.
5. Try it in the **Preview** tab with a question, then select **Create** to publish it. It is private
   to you until you share it (**Actions menu → Share**).

**Option 2, register an agent by its card.** Works with any Gemini Enterprise app in the project.

1. In the Google Cloud console open the **Gemini Enterprise** page and click the name of the app your
   instructor prepared.
2. Click **Agents**, then **Add Agents**.
3. Under **Choose an agent type**, click **Add** for **Custom agent via A2A**.
4. In **Agent card JSON** paste the card from Appendix A with `STUDENT` replaced by your initials.
5. Click **Preview agent details**, check the name, description and skills the console read from the
   card, then **Next**. Skip the authorization settings (they are for agents that need to sign users
   in) and finish the wizard.
6. The agent is listed on the app's **Agents** page. Because its address is a placeholder it will not
   answer questions; registration does not require a working agent.

> **Governance note.** Option 1 is how most agents will appear in organizations: created by business
> users in minutes, without a developer. Option 2 is how agents built elsewhere are brought under
> the same roof. In both cases the platform, not the person, adds the agent to the registry.

### B2. Find the agent in Agent Registry (Consumer, Auditor)

1. In the Google Cloud console search bar type **Agent Registry** and open the Agent Registry page of
   Gemini Enterprise Agent Platform.
2. Make sure the project and the location match the ones your instructor named.
3. Find your agent in the list of agents. Entries created from Gemini Enterprise appear
   automatically; allow a few minutes.
4. Open it. Compare what the registry knows (name, description, skills, the address, the hosting
   environment when known) with what you entered.
5. Use the search box to find it by a word from its description or a skill tag.

> **Governance note.** This catalog has no approval button. Governance happens through *who may do
> what*: readers get the viewer role (`roles/agentregistry.viewer`), administrators get the admin
> role (`roles/agentregistry.admin`), and Google warns against giving the admin role to agents
> themselves. Policy enforcement at run time is handled by other components of the platform (Agent
> Gateway and Agent Identity), not by the catalog.

## Part C: Compare and reflect

Discuss in your group and write short answers for your lab report.

| Question | AWS Agent Registry | Gemini Enterprise Agent Platform |
| --- | --- | --- |
| Who can add an agent to the catalog? | | |
| Is a human approval required before others can find it? Where is that decided? | | |
| What evidence does the catalog keep about a decision (who, when, why)? | | |
| How is an agent retired, and can a retired entry come back? | | |
| Who can read the catalog, and how is that controlled? | | |
| Which agents get into the catalog automatically, and which must be registered by hand? | | |

Then consider the gap between the catalog and reality:

1. Your *Holiday Helper* record on AWS describes an agent that does not exist. Which control in the
   lab would have caught that? Which control in a real organization should?
2. Suppose a team deploys an agent on a cloud server and never registers it. Which of the two
   catalogs would notice? (Neither; a registry records what is submitted or detected on its own
   runtimes. Independent discovery, for example by scanning cloud accounts the way ShadowScan
   does, closes that gap.)
3. The AWS curator wrote a free-text reason. Draft three fields you would make mandatory instead,
   and say who should be allowed to fill them in.
4. Google Cloud separates *viewer* and *admin* roles; AWS separates *publisher*, *curator* and
   *consumer* permissions. Map these onto the roles in your organization's AI policy.

## Part D: Clean up

AWS: in the **Registry records** list delete every record you created (deprecated and rejected ones
included), then open the registry and choose **Delete**. A registry with records cannot be deleted.

Google Cloud: in the Gemini Enterprise app remove the agent you created (Agents page, the agent's
menu, **Delete**; for an Agent Designer agent use its **Actions menu**). The Agent Registry entry
disappears with it. Your instructor deletes the sandbox project afterwards.

## Appendix A: the agent card to paste

Replace every `STUDENT` with your initials, lowercase, no spaces. Keep every quotation mark and
comma exactly as shown. The address ends in `.invalid`, a domain that can never exist, so nobody can
mistake the lab agent for a real one.

```json
{
  "protocolVersion": "0.3.0",
  "name": "holiday-helper-STUDENT",
  "description": "Answers employee questions about the company holiday calendar. Demonstration agent from the AI governance lab.",
  "url": "https://lab.example.invalid/agents/holiday-helper-STUDENT",
  "version": "1.0.0",
  "capabilities": {"streaming": false},
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "skills": [
    {
      "id": "holiday-questions",
      "name": "Holiday questions",
      "description": "Answers questions about public holidays and company closure days.",
      "tags": ["lab", "hr"]
    }
  ]
}
```

## Appendix B: glossary

| Term | Meaning |
| --- | --- |
| A2A | Agent-to-agent protocol: an open standard for how agents describe themselves (the agent card) and talk to each other. |
| ARN | Amazon Resource Name, the unique identifier of anything in AWS. |
| Approval gate | A step where a human must approve an entry before it becomes visible or usable. |
| Curator | The person or team accountable for reviewing registry submissions. |
| Deprecated | Retired. On AWS a final state: the entry stays for the record but is hidden from consumers. |
| Discovery | Finding an agent or tool in a catalog, by browsing or searching. Also what one agent does to find another. |
| IAM, role | The permission systems of AWS (IAM) and Google Cloud (roles). They decide who can create, approve, read or delete. |
| MCP | Model Context Protocol, a standard for tools that agents can call. Both registries also list MCP servers, and both can be read by agents through MCP. |
| Runtime | The service that actually runs an agent (AgentCore Runtime on AWS, Agent Runtime on Google Cloud). |
| Shadow AI | AI agents and integrations that operate without the organization's knowledge or approval. |

## Instructor preparation

* **Accounts.** One sandbox AWS account and one sandbox Google Cloud project, deleted or emptied after
  the session. Use a Region and location where both services are available (for example
  `us-east-1` and `us-central1`).
* **AWS logins.** Console users with permission for the `agent-registry:*` actions in the sandbox
  account. For a separation-of-duties exercise, give publishers `CreateRegistryRecord`,
  `GetRegistryRecord`, `ListRegistryRecords` and `SubmitRegistryRecordForApproval`; curators
  additionally `UpdateRegistryRecordStatus`; consumers only `ListDiscoverableRegistryRecords` and
  `SearchDiscoverableRegistryRecords`. Registry creation (A1) can be done by you in advance.
* **Google Cloud logins.** `roles/agentregistry.viewer` for everyone, `roles/agentregistry.admin`
  for whoever cleans up, the Agent Registry API enabled, and either a Gemini Enterprise edition with
  Agent Designer (Option 1) or a Gemini Enterprise app in the project to which students may add
  agents (Option 2). Verify the week before: entitlements and console labels change.
* **Seed data.** Run the technical notebook (`agent-registry-lab.ipynb`, same folder) once before
  class, without its cleanup cell, so that both catalogs already contain an example agent for students
  to discover before they register their own.
* **Evidence to collect.** Ask students to screenshot the registry ARN, each status change, the
  approval and rejection reasons, the discovery view before and after deprecation, and the Agent
  Registry entry on Google Cloud. These screenshots are the lab report.
* **Console drift.** This guide reflects the consoles as documented in October 2026. Menu labels
  move; the sequence (create catalog, submit, approve with a reason, discover, retire) does not.

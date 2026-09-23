resource "aws_bedrockagent_agent" "ops" {
  agent_name              = "ops-provisioning-04"
  agent_resource_role_arn = aws_iam_role.agent.arn
  foundation_model        = "anthropic.claude-3-5-sonnet-20241022-v2:0"
  instruction             = "You are an ops agent that provisions infrastructure."
}
resource "aws_bedrockagent_agent_action_group" "lambda" {
  agent_id = aws_bedrockagent_agent.ops.id
  action_group_executor { lambda = aws_lambda_function.tools.arn }
}
resource "aws_iam_role_policy" "agent" {
  policy = jsonencode({ Statement = [{ Action = ["bedrock:InvokeModel", "bedrock:InvokeAgent", "s3:*"], Effect = "Allow", Resource = "*" }] })
}
resource "google_dialogflow_cx_agent" "cx" {
  display_name = "helpdesk"
}

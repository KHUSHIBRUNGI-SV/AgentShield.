import { expect, test } from "@playwright/test";

const api = "http://127.0.0.1:8765";

test("authenticated decisions and audit records appear in the reviewer dashboard", async ({
  page,
  request,
}) => {
  const agentLogin = await request.post(`${api}/auth/login`, {
    data: {
      username: "customer_support_bot",
      password: "e2e-agent-password",
    },
  });
  expect(agentLogin.ok()).toBeTruthy();
  const agentToken = (await agentLogin.json()).access_token as string;
  const agentHeaders = { Authorization: `Bearer ${agentToken}` };

  const allowed = await request.post(`${api}/check-action`, {
    headers: agentHeaders,
    data: {
      agent: "customer_support_bot",
      user: "customer_support_bot",
      tool: "customer.lookup",
      action: "read",
      resource: "customer",
      environment: "development",
      records: 1,
    },
  });
  expect(allowed.ok()).toBeTruthy();
  expect((await allowed.json()).decision).toBe("ALLOW");

  const blocked = await request.post(`${api}/check-action`, {
    headers: agentHeaders,
    data: {
      agent: "customer_support_bot",
      user: "customer_support_bot",
      tool: "credential.dump",
      action: "export",
      resource: "secrets",
      environment: "production",
      records: 50,
    },
  });
  expect(blocked.ok()).toBeTruthy();
  expect((await blocked.json()).decision).toBe("BLOCK");

  const approvalRequest = await request.post(`${api}/check-action`, {
    headers: agentHeaders,
    data: {
      agent: "customer_support_bot",
      user: "customer_support_bot",
      tool: "customer.export",
      action: "export",
      resource: "customer",
      environment: "development",
      records: 1,
    },
  });
  expect(approvalRequest.ok()).toBeTruthy();
  const pending = await approvalRequest.json();
  expect(pending.decision).toBe("HUMAN_APPROVAL");

  const reviewerLogin = await request.post(`${api}/auth/login`, {
    data: {
      username: "e2e_reviewer",
      password: "e2e-reviewer-password",
    },
  });
  expect(reviewerLogin.ok()).toBeTruthy();
  const reviewerToken = (await reviewerLogin.json()).access_token as string;
  const reviewerHeaders = { Authorization: `Bearer ${reviewerToken}` };
  const reviewed = await request.post(`${api}/approvals/decision`, {
    headers: reviewerHeaders,
    data: { approval_id: pending.approval_id, approved: true },
  });
  expect(reviewed.ok()).toBeTruthy();
  expect((await reviewed.json()).decision).toBe("EXECUTION_UNAVAILABLE");

  const audit = await request.get(`${api}/audit-logs`, {
    headers: reviewerHeaders,
  });
  expect(audit.ok()).toBeTruthy();
  const auditEvents = (await audit.json()).audit_logs as Array<{
    decision: string;
    tool: string;
  }>;
  expect(auditEvents.map((event) => event.decision)).toEqual(
    expect.arrayContaining([
      "ALLOW",
      "BLOCK",
      "HUMAN_APPROVAL",
      "EXECUTION_UNAVAILABLE",
    ]),
  );

  await page.goto("/");
  await page.getByLabel("Account ID").fill("e2e_reviewer");
  await page.getByLabel("Password").fill("e2e-reviewer-password");
  await page.getByRole("button", { name: /Authenticate/ }).click();
  await expect(page.getByRole("heading", { name: /Your agents/ })).toBeVisible();
  await page.getByRole("button", { name: "Audit logs" }).click();
  await expect(page.getByRole("heading", { name: "Audit logs" })).toBeVisible();
  await expect(page.getByText("customer.lookup").first()).toBeVisible();
  await expect(page.getByText("credential.dump").first()).toBeVisible();
  await expect(page.getByText("customer.export").first()).toBeVisible();
});

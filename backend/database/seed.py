from database.database import SessionLocal
from database.models import Agent, Permission, Policy


db = SessionLocal()


# ==========================================
# CUSTOMER SUPPORT BOT
# ==========================================

support_bot = Agent(
    name="customer_support_bot",
    description="AI agent used for customer support operations"
)

db.add(support_bot)
db.commit()
db.refresh(support_bot)


support_read = Permission(
    agent_id=support_bot.id,
    resource="customer",
    action="read"
)

support_update = Permission(
    agent_id=support_bot.id,
    resource="customer",
    action="update"
)

support_export = Permission(
    agent_id=support_bot.id,
    resource="customer",
    action="export"
)

db.add_all([
    support_read,
    support_update,
    support_export
])

db.commit()

db.refresh(support_read)
db.refresh(support_update)
db.refresh(support_export)


# ==========================================
# SUPPORT POLICIES
# ==========================================

support_read_policy = Policy(
    permission_id=support_read.id,
    environment="*",
    max_requests_per_minute=20
)

support_update_policy = Policy(
    permission_id=support_update.id,
    environment="development",
    max_requests_per_minute=10
)

support_export_policy = Policy(
    permission_id=support_export.id,
    environment="*",
    max_records=1000,
    max_requests_per_minute=5,
    requires_approval=False
)

db.add_all([
    support_read_policy,
    support_update_policy,
    support_export_policy
])


# ==========================================
# ADMIN BOT
# ==========================================

admin_bot = Agent(
    name="admin_bot",
    description="AI agent used for administrative operations"
)

db.add(admin_bot)
db.commit()
db.refresh(admin_bot)


admin_read = Permission(
    agent_id=admin_bot.id,
    resource="customer",
    action="read"
)

admin_update = Permission(
    agent_id=admin_bot.id,
    resource="customer",
    action="update"
)

admin_delete = Permission(
    agent_id=admin_bot.id,
    resource="customer",
    action="delete"
)

admin_export = Permission(
    agent_id=admin_bot.id,
    resource="customer",
    action="export"
)

db.add_all([
    admin_read,
    admin_update,
    admin_delete,
    admin_export
])

db.commit()

db.refresh(admin_read)
db.refresh(admin_update)
db.refresh(admin_delete)
db.refresh(admin_export)


# ==========================================
# ADMIN POLICIES
# ==========================================

admin_read_policy = Policy(
    permission_id=admin_read.id,
    environment="*",
    max_requests_per_minute=50
)

admin_update_policy = Policy(
    permission_id=admin_update.id,
    environment="*",
    max_requests_per_minute=30
)

# Delete is allowed only in development
admin_delete_policy = Policy(
    permission_id=admin_delete.id,
    environment="development",
    max_requests_per_minute=5
)

# Large exports require human approval
admin_export_policy = Policy(
    permission_id=admin_export.id,
    environment="*",
    max_records=10000,
    max_requests_per_minute=10,
    requires_approval=True
)

db.add_all([
    admin_read_policy,
    admin_update_policy,
    admin_delete_policy,
    admin_export_policy
])


db.commit()

print("Agents, permissions, and policies added successfully!")

db.close()
POLICIES = {
    "customer_support_bot": {
        "allowed": [
            "customer.read",
            "customer.update",
            "customer.export"
        ],

        "restricted_environments": {
            "customer.update": ["production"]
        },

        "limits": {
            "customer.export": {
                "max_records": 1000
            }
        }
    },

    "admin_bot": {
        "allowed": [
            "customer.read",
            "customer.update",
            "customer.delete",
            "customer.export"
        ],

        "restricted_environments": {
            "customer.delete": ["production"]
        },

        "limits": {
            "customer.export": {
                "max_records": 10000
            }
        }
    }
}
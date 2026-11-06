import sys


def main() -> int:
    try:
        from database.database import DATABASE_MODE, engine
    except RuntimeError as error:
        print(f"Database connection was not attempted: {error}")
        return 1

    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
    except Exception as error:
        print(
            "Database connection failed "
            f"({type(error).__name__}). Check DATABASE_URL and database service."
        )
        return 1

    print(f"Database connected successfully ({DATABASE_MODE}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
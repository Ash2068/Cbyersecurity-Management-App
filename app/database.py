from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# SQLite for now -- swap this connection string for Postgres/MySQL when you go to prod.
# e.g. "postgresql://user:pass@host/dbname"
SQLALCHEMY_DATABASE_URL = "sqlite:///./logon_ai.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
